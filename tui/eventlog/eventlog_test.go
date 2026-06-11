package eventlog

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// a valid-format fingerprint (SHA256: + 43 base64 chars), so events pass the
// schema's fpr pattern.
const fpr = "SHA256:zz6S5e54kc2bpWt6SqcgqSNN/Yrx91Vko0Kz6g3IVWM"
const fpr2 = "SHA256:aa6S5e54kc2bpWt6SqcgqSNN/Yrx91Vko0Kz6g3IVWM"

func sampleEvents() []Event {
	return []Event{
		Join("ops", "alice", fpr, false),
		Leave("ops", "alice", fpr),
		Message("ops", "alice", fpr, true, false, "the database is on fire", false),
		Message("ops", "alice", fpr, true, true, "with body", true),
		Vanish("ops", "alice", fpr),
		Scuttle("ops", "idle"),
		BeaconSet("ops", "alice", fpr, 3600),
		BeaconCleared("ops", "alice", fpr),
		FileOffer("ops", "alice", fpr, "heap.prof", 4194304, "3f9a2b71c4d5e6f0"),
		FileComplete("ops", "alice", fpr, "heap.prof", 4194304, "3f9a2b71c4d5e6f0", true),
		Ack("ops", "alice", fpr, "drain-complete", "3/6"),
		Handoff("ops", "alice", fpr, "bob", fpr2),
		ActionRequest("ops", "alice", fpr, "scuttle", "a3f9c1d2e4b5a6f7", 2, 1749230400),
		ActionApproval("ops", "bob", fpr2, "a3f9c1d2e4b5a6f7", 2, 2),
		ActionExecuted("ops", "alice", fpr, "a3f9c1d2e4b5a6f7", "scuttle", 2),
		ActionVetoed("ops", "bob", fpr2, "a3f9c1d2e4b5a6f7", "scuttle", "wrong room"),
		ActionExpired("ops", "a3f9c1d2e4b5a6f7", "scuttle", 1, 2),
		RouteFired("inc-3f9a2b71", 0, []string{"alice", "bob"}, 7200),
		Verify("ops", "alice", fpr, "bob", fpr2, true),
		ExecRequest("ops", "alice", fpr, "drain", Bool(true)),
		ExecRequest("ops", "alice", fpr, "drain", nil),
		ExecResult("ops", "agent-host", fpr, "drain", true, 0),
		KeyReady("ops", 0),
		StreamUpdate("ops", "alice", fpr, "3f9a2b71c4d5e6f0"),
		StreamEnd("ops", "3f9a2b71c4d5e6f0", "sender_disconnected"),
		ClockStart("ops", "alice", fpr),
		ClockStop("ops", "alice", fpr, 2843),
		ErrorEvent("ops", "something went wrong"),
		Disconnect("ops", "connection closed (code 1000)"),
	}
}

func TestEventRoundTrip(t *testing.T) {
	for _, e := range sampleEvents() {
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("marshal %s: %v", e.Type, err)
		}
		var got Event
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields() // every emitted field must be a known struct field
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("unmarshal %s: %v\n%s", e.Type, err, b)
		}
		if !reflect.DeepEqual(e, got) {
			t.Fatalf("round-trip changed %s event:\n in: %+v\nout: %+v", e.Type, e, got)
		}
		if got.V != SchemaVersion {
			t.Errorf("%s event missing v=%d", e.Type, SchemaVersion)
		}
	}
}

func TestBodyHashVector(t *testing.T) {
	// Known SHA-256 of "hello".
	const want = "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got := HashBody("hello"); got != want {
		t.Fatalf("HashBody:\n got %s\nwant %s", got, want)
	}
	// And the message event carries that exact hash + the byte length.
	e := Message("ops", "alice", fpr, true, false, "hello", false)
	if e.BodyHash != want {
		t.Errorf("message body_hash = %s", e.BodyHash)
	}
	if e.BodyLen == nil || *e.BodyLen != 5 {
		t.Errorf("message body_len = %v", e.BodyLen)
	}
}

func TestMessageIncludeBodies(t *testing.T) {
	without := Message("ops", "alice", fpr, true, false, "secret creds", false)
	if without.Body != "" {
		t.Error("body must be absent by default")
	}
	with := Message("ops", "alice", fpr, true, false, "secret creds", true)
	if with.Body != "secret creds" {
		t.Errorf("--include-bodies should add the body, got %q", with.Body)
	}
	// body_hash/body_len identical regardless of inclusion.
	if without.BodyHash != with.BodyHash || *without.BodyLen != *with.BodyLen {
		t.Error("hash/len should not depend on body inclusion")
	}
}

func TestSchemaValidatesEvents(t *testing.T) {
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft7
	if err := c.AddResource("event.json", strings.NewReader(SchemaJSON())); err != nil {
		t.Fatalf("add schema (is it valid JSON?): %v", err)
	}
	// Compiling under Draft7 proves the embedded document is a valid draft-07 schema.
	sch, err := c.Compile("event.json")
	if err != nil {
		t.Fatalf("schema is not valid draft-07: %v", err)
	}

	// Every constructed event validates against the schema.
	for _, e := range sampleEvents() {
		var doc any
		b, _ := json.Marshal(e)
		_ = json.Unmarshal(b, &doc)
		if err := sch.Validate(doc); err != nil {
			t.Fatalf("%s event failed schema validation: %v\n%s", e.Type, err, b)
		}
	}

	// And the validator actually rejects malformed events (not just "it parses").
	bad := []map[string]any{
		{"v": 1, "ts": "2026-06-06T03:14:22Z", "type": "join", "actor": "a", "extra": "nope"}, // additionalProperties:false
		{"v": 2, "ts": "2026-06-06T03:14:22Z", "type": "join"},                                // wrong version (const 1)
		{"v": 1, "ts": "2026-06-06T03:14:22Z", "type": "nonsense"},                            // not in type enum
		{"v": 1, "ts": "2026-06-06T03:14:22Z", "type": "message", "fpr": "not-a-fingerprint"}, // fpr pattern
		{"v": 1, "type": "join"}, // missing ts
	}
	for i, b := range bad {
		if err := sch.Validate(any(b)); err == nil {
			t.Errorf("malformed event %d should have failed validation", i)
		}
	}
}
