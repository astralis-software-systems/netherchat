package app

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/tui/attest"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// The read-side issuer pin (D-L), and the evaluation time a live surface has to
// invent because nothing signs one for it.
//
// # WHY A SCREEN MAY PIN A KEY WHEN A PRODUCER MAY NOT
//
// Roadmap §6 rule 1 used to read "there is no --issuer flag on connect". That
// sentence was a proxy for the rule it was protecting, and it was broader than
// the rule: what must never happen is a PRODUCER making evidence a function of
// its own configuration — a client that refuses to carry a credential because
// its own operator pinned nothing, a record whose contents differ depending on
// who wrote it, an approval whose role depends on the approver's key file. None
// of that is a screen. A record is still verified at its reader with the
// reader's key, and nothing rendered here enters any record.
//
// So the rule now reads: NO ISSUER CONFIGURATION ON ANY PATH THAT PRODUCES
// EVIDENCE. The keys below are read in exactly one function, and
// TestTheIssuerPinIsReadByOneFunction is what keeps that from drifting.
//
// # WHERE THE EVALUATION TIME COMES FROM, AND WHAT IT COSTS
//
// A record carries signed timestamps to evaluate against, and §5.6 of the
// identity spec brackets them. A participants panel carries none. Presence is
// now, so the evaluation time here is THE INSTANT THE CHECK RAN — read by
// whatever event triggered the check, passed in, and never read inside this file
// (TestTheAttributionDecisionReadsNoClock). A rendered row therefore says what
// it says because of when it was DECIDED, not because of when it was drawn:
// a view function that read a clock would re-verify on every keystroke and
// produce a state nothing could golden.
//
// Two consequences, both stated rather than mitigated:
//
//   - The clock is this machine's own and nothing signs it. A reader whose clock
//     is wrong renders ◆ wrongly, and unlike a record there is no second
//     timestamp to bracket it against. /issuer says so in as many words.
//   - A credential expires mid-session and the panel has to notice. It does, on
//     the room tick and on nothing else — see nextClockEvent.

// IssuerPin is what `connect --issuer <file>` produced: the trust anchors an
// operator supplied, and the path they named. Both halves matter — the keys
// decide what ◆ means and the path is how /issuer answers "against what".
//
// An empty IssuerPin is not "an empty pin". It is no pin, and it is the state
// every client is in unless somebody typed the flag.
type IssuerPin struct {
	Keys   []ed25519.PublicKey
	Source string
}

func (p IssuerPin) pinned() bool { return len(p.Keys) > 0 }

// usePin installs the operator's trust anchors, and derives here the two things
// a SCREEN needs to know about them: whether there are any, and what they are
// called.
//
// The derivation is the point. Rendering surfaces want a boolean ("say 'not
// checked here' or don't") and a list of fingerprints (/issuer), and neither is
// key material. Deriving them once means the keys themselves are named in
// exactly two functions — here and in attribute — so the single-reader guard
// stays as tight as the rule it enforces, instead of being widened to admit a
// length check that any future evidence path could then also make.
func (m *Model) usePin(p IssuerPin) {
	m.pinnedIssuerKeys = p.Keys
	m.issuerSource = p.Source
	m.issuerFprs = nil
	for _, k := range p.Keys {
		m.issuerFprs = append(m.issuerFprs, crypto.Fingerprint(k))
	}
}

// pinned reports whether this client can check anything at all.
func (m *Model) pinned() bool { return len(m.issuerFprs) > 0 }

// attribute resolves one participant's D-I attribution and says when, if ever,
// the clock could change the answer.
//
// asserted is the name the sender chose. subjectFpr is the fingerprint of the
// key being rendered — the join that turns a signed statement into a statement
// about THIS participant, which is why IdentityDisplayFor takes it positionally.
// at is the evaluation time.
//
// WITH NO KEY PINNED, NOTHING IS ATTEMPTED. That is different from attempting a
// verification with an empty key set: the verifier answers an empty key set with
// a result, and a result carries an outcome code and a detail sentence that an
// unpinned surface has never shown. Handing a nil result to the decision is what
// keeps the unpinned rendering identical to the tree before this file existed —
// TestTheVerifiedMarkStaysUnreachableWithNoIssuerPinned fails on the difference,
// and TestPresenceInertWithCredentialsAndNoIssuerPinned compares the bytes.
func (m *Model) attribute(asserted, subjectFpr string, carried *attest.IdentityAttestation, at time.Time) (attest.IdentityDisplay, time.Time) {
	if len(m.pinnedIssuerKeys) == 0 || carried == nil {
		return attest.IdentityDisplayFor(asserted, subjectFpr, carried, nil), time.Time{}
	}
	res, err := attest.VerifyIdentity(carried, attest.IdentityOptions{IssuerKeys: m.pinnedIssuerKeys, At: at})
	if err != nil {
		// The verifier rejects a call it cannot answer — a zero evaluation time is
		// the only one reachable from here — rather than returning a verdict. There
		// is no verdict to render, so the row renders as a claim that arrived.
		return attest.IdentityDisplayFor(asserted, subjectFpr, carried, nil), time.Time{}
	}
	d := attest.IdentityDisplayFor(asserted, subjectFpr, carried, res)
	return d, nextClockEvent(d, res)
}

// attributeBytes is attribute for a surface holding the raw carrier bytes.
// Bytes that are not an identity artifact land in the carried state rather than
// the asserted one, because something did arrive.
func (m *Model) attributeBytes(asserted, subjectFpr string, carried []byte, at time.Time) (attest.IdentityDisplay, time.Time) {
	if len(carried) == 0 {
		return m.attribute(asserted, subjectFpr, nil, at)
	}
	a, err := attest.ParseIdentity(carried)
	if err != nil {
		return attest.IdentityDisplayForBytes(asserted, subjectFpr, carried, nil), time.Time{}
	}
	return m.attribute(asserted, subjectFpr, a, at)
}

// nextClockEvent returns the earliest instant at which re-running the check
// could produce a different answer, or the zero time when no instant can.
//
// Only the WINDOW moves. The bytes are fixed, the pinned keys are fixed for the
// session, and no revocation statement is supplied to a live surface — so a row
// that failed on a signature, on a subject join, or on an unpinned authority
// will fail the same way forever, and re-verifying it on a timer would spend an
// Ed25519 check every fifteen seconds to arrive back where it started.
//
// A verified row can only stop being verified when its window closes, and a
// not-yet-valid row can only start when its window opens. Those are the two
// instants, and they are both in the result the issuer signed.
func nextClockEvent(d attest.IdentityDisplay, res *attest.IdentityResult) time.Time {
	if res == nil {
		return time.Time{}
	}
	switch {
	case d.State == attest.IdentityDisplayVerifiedNamed || d.State == attest.IdentityDisplayVerifiedUnnamed:
		// Containment is closed at both ends, so the first instant this stops
		// verifying is one tick after the window's end.
		if t, err := time.Parse(time.RFC3339, res.NotAfter); err == nil {
			return t.Add(time.Nanosecond)
		}
	case d.Reason == attest.ReasonNotYetValid:
		if t, err := time.Parse(time.RFC3339, res.NotBefore); err == nil {
			return t
		}
	}
	return time.Time{}
}

// recheckIdentities re-decides every attribution whose window boundary the clock
// has now crossed, across every joined room and the operator's own credential.
// It returns whether anything on screen changed, so the caller can decide
// whether to redraw.
//
// This is the answer to "what happens when a credential expires mid-session":
// the panel changes here, on the room tick, and nowhere else. Not on a message,
// not on a keystroke, not on a redraw — expiry is a clock event and the clock is
// the only thing that reports it. The tick is 15 seconds (tickEvery), so that is
// the granularity of the answer, and it is stated rather than implied.
func (m *Model) recheckIdentities(now time.Time) bool {
	m.lastCheckedAt = now
	changed := false
	for _, r := range m.session {
		for id, mem := range r.members {
			if !due(mem.recheckAt, now) {
				continue
			}
			d, next := m.attributeBytes(mem.name, mem.fpr, mem.carried, now)
			if !sameDisplay(d, mem.identity) {
				changed = true
			}
			mem.identity, mem.recheckAt = d, next
			r.members[id] = mem
		}
	}
	if m.credential != nil && due(m.ownRecheckAt, now) {
		d, next := m.attribute(m.name, m.fingerprint, m.credential, now)
		if !sameDisplay(d, m.ownIdentity) {
			changed = true
		}
		m.ownIdentity, m.ownRecheckAt = d, next
	}
	return changed
}

// due reports whether a scheduled clock event has arrived. The zero time means
// no event is scheduled, which is the common case.
func due(at, now time.Time) bool { return !at.IsZero() && !now.Before(at) }

// sameDisplay compares two attributions. IdentityDisplay holds a role slice, so
// it is not comparable with ==, and a re-check that reported "changed" on every
// tick would redraw the room fifteen times a minute for nothing.
func sameDisplay(a, b attest.IdentityDisplay) bool {
	if a.State != b.State || a.Name != b.Name || a.Principal != b.Principal ||
		a.DisplayName != b.DisplayName || a.Issuer != b.Issuer ||
		a.Reason != b.Reason || a.ReasonClass != b.ReasonClass || a.Detail != b.Detail {
		return false
	}
	if len(a.Roles) != len(b.Roles) {
		return false
	}
	for i := range a.Roles {
		if a.Roles[i] != b.Roles[i] {
			return false
		}
	}
	return true
}

// useCredential installs the operator's own attestation and resolves what this
// client can say about it, at the given time. It is called once when the
// credential arrives from --attestation and again once the BYO-key cascade has
// decided which key it is supposed to be about, because the subject join needs
// that fingerprint and it does not exist before a connect.
func (m *Model) useCredential(a *attest.IdentityAttestation, at time.Time) {
	m.credential = a
	if a == nil {
		m.ownIdentity, m.ownRecheckAt = attest.IdentityDisplay{}, time.Time{}
		return
	}
	m.ownIdentity, m.ownRecheckAt = m.attribute(m.name, m.fingerprint, a, at)
}

// runIssuer implements /issuer. It REPORTS and it cannot configure, and the
// refusal below is the whole reason it is safe to have at all.
//
// ◆ now rests on something that is nowhere on the screen: a file this client was
// started with. A person looking at a diamond has to be able to ask what it was
// checked against, and this is where they ask. What they must not be able to do
// is pin a key from here — a second place to install a trust anchor is a second
// posture (a startup flag fails the connect; a command can only complain into a
// room and carry on), and an operator who typed a path and got a complaint they
// scrolled past would be looking at an unpinned screen believing otherwise.
func (m *Model) runIssuer(arg string) {
	if strings.TrimSpace(arg) != "" {
		m.addError("/issuer takes no argument — it reports the pin, it does not set one.\n" +
			"  an issuer key is pinned for a whole session at startup:  netherchat connect --issuer <file>\n" +
			"  the pin changes what this screen renders and nothing else: no record, roster or approval\n" +
			"  this client produces depends on it.")
		return
	}
	m.addSystem(m.issuerText())
}

// issuerText is /issuer's body: what is pinned, what it was checked against, and
// when — and, unpinned, why the strongest mark in the vocabulary is absent
// rather than unearned.
func (m *Model) issuerText() string {
	var b strings.Builder
	if !m.pinned() {
		b.WriteString("issuer pin:  none\n")
		b.WriteString("  this client pins no issuer key, so ◆ is not a state any row here can reach.\n")
		b.WriteString("  a credential that arrives is shown as the claim it is (◇) under the name its\n")
		b.WriteString("  sender chose.\n")
		b.WriteString("  to check them against an authority:  netherchat connect --issuer <file>\n")
		b.WriteString("  a record is checked by whoever reads it, with their own key, either way:\n")
		b.WriteString("    netherchat verify <record.json> --issuer <file>")
		return b.String()
	}
	fmt.Fprintf(&b, "issuer pin:  %d key(s) from %s\n", len(m.issuerFprs), m.issuerSource)
	for _, f := range m.issuerFprs {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	b.WriteString("  ◆ marks a credential checked here against one of those keys, for a window that\n")
	b.WriteString("    contained the evaluation time.\n")
	if !m.lastCheckedAt.IsZero() {
		fmt.Fprintf(&b, "  last checked at %s, by this machine's own clock.\n"+
			"    Nothing signs that clock, and a wrong one renders a wrong mark. A record has two\n"+
			"    signed timestamps to bracket; a room has none.\n",
			m.lastCheckedAt.UTC().Format(time.RFC3339))
	} else {
		b.WriteString("  nothing has been checked yet in this session.\n")
	}
	b.WriteString("  this pin is yours. It changes what this screen renders and nothing else — the\n")
	b.WriteString("  records, rosters and approvals this client produces are byte-identical with it\n")
	b.WriteString("  and without it, and their readers supply their own key.")
	return b.String()
}
