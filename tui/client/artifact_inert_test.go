package client

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/record"
)

// STANDALONE-INERT ON THE APPROVAL PATH (roadmap §6 rule 4, identity spec §9).
//
// Both goldens under testdata/ were captured from the tree BEFORE Attestation
// and Role existed on protocol.ArtifactApprovalBody. They are compared against,
// never re-derived: an approver who carries no credential must put the same
// bytes on the wire and the same record on disk as they did then.
//
//	approval_wire_v1.json          the marshalled wire body, exact bytes
//	unattested_record_v1.json      a real end-to-end sealed record, exact bytes
//	unattested_record_v1.proposal  its proposal id
const (
	wireGolden     = "testdata/approval_wire_v1.json"
	recordGolden   = "testdata/unattested_record_v1.json"
	proposalGolden = "testdata/unattested_record_v1.proposal"
)

func readGolden(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestUnattestedApprovalWireBytesUnchanged pins the omitempty claim: with no
// credential carried and no role signed, the body marshals to the bytes it
// marshalled to before either field existed. That is what makes this change
// additive rather than a version bump — an old peer sees a frame it already
// understands, byte for byte.
func TestUnattestedApprovalWireBytesUnchanged(t *testing.T) {
	got, err := json.Marshal(protocol.ArtifactApprovalBody{
		ProposalID:   "0123456789abcdef",
		ArtifactHash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ApproverFpr:  "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Sig:          []byte{0x01, 0x02, 0x03, 0x04},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := readGolden(t, wireGolden)
	if !bytes.Equal(got, want) {
		t.Fatalf("the unattested approval body no longer marshals to its pre-change bytes:\n got %s\nwant %s", got, want)
	}
}

// TestPreChangeRecordStillVerifies re-verifies the captured record itself. The
// reader half of the approval path has to keep reading what the writer half
// wrote before this change: one roleless proof, and no role-typed surface.
func TestPreChangeRecordStillVerifies(t *testing.T) {
	b := readGolden(t, recordGolden)
	id := string(readGolden(t, proposalGolden))
	rec, err := record.Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	proofs := rec.ArtifactApprovals[id]
	if len(proofs) != 1 || proofs[0].Role != "" {
		t.Fatalf("the pre-change record carries one roleless proof, got %+v", proofs)
	}
	res, err := record.Verify(rec)
	if err != nil || !res.Valid {
		t.Fatalf("the pre-change record must still verify: err=%v reason=%q", err, res.Reason)
	}
	// The sole approver authored the artifact entry, so the second-person surface
	// is legitimately empty; what must stay empty either way is the role-typed one.
	if roles := record.VerifiedArtifactApproverRoles(res, id); len(roles) != 0 {
		t.Fatalf("a pre-change record carries no role-typed approvals, got %v", roles)
	}
}

// TestUnattestedSealedRecordShapeUnchanged runs the full unattested flow again
// and compares the JSON SHAPE — every key path at every level — against the
// captured record. Values are clocks, fingerprints and signatures and differ per
// run; a new key would not, and that is what this catches.
func TestUnattestedSealedRecordShapeUnchanged(t *testing.T) {
	_, agent, alice := twoClients(t, "ops")
	hash := hashOf("DRAFT_REQUIREMENTS_v1")
	id, err := agent.Propose("requirements-agent", "Q3-requirements", hash, "draft for review", 1)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	waitFor[EvArtifactProposed](t, alice, 5*time.Second)
	if err := alice.ApproveArtifact(id, ""); err != nil {
		t.Fatalf("approve: %v", err)
	}
	waitFor[EvArtifactSealed](t, alice, 5*time.Second)
	_ = agent.Close()
	waitFor[EvMemberLeft](t, alice, 5*time.Second)
	if err := alice.Seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	fresh, err := waitFor[EvSealComplete](t, alice, 20*time.Second).Record.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got := jsonShape(t, fresh)
	want := jsonShape(t, readGolden(t, recordGolden))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("an unattested seal no longer has the pre-change record shape:\n got %v\nwant %v", got, want)
	}
}

// dataKey matches a map key that is DATA rather than schema — a fingerprint or a
// 16-hex proposal id. Those differ every run; the schema around them must not.
var dataKey = regexp.MustCompile(`^(SHA256:.+|[0-9a-f]{16})$`)

// jsonShape reduces a JSON document to its sorted key paths. Entry bodies are
// signed strings holding their own JSON object, so they are descended into as
// well: an artifact entry's body is where a field would most plausibly appear.
func jsonShape(t *testing.T, b []byte) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	seen := map[string]bool{}
	var walk func(prefix string, node any)
	walk = func(prefix string, node any) {
		switch x := node.(type) {
		case map[string]any:
			for k, sub := range x {
				if dataKey.MatchString(k) {
					k = "*"
				}
				p := prefix + "." + k
				seen[p] = true
				walk(p, sub)
			}
		case []any:
			for _, sub := range x {
				walk(prefix+"[]", sub)
			}
		case string:
			var inner any
			if json.Unmarshal([]byte(x), &inner) == nil {
				if _, ok := inner.(map[string]any); ok {
					walk(prefix+"~", inner)
				}
			}
		}
	}
	walk("", v)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
