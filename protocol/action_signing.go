package protocol

import "bytes"

// ActionApprovalSigningBytes returns the canonical bytes an action approval
// covers (the Two-Person Rule, §1.3): an authorized member attesting "I endorse
// this exact privileged action." The preimage is domain-separated and binds, in
// order, the request id, the params hash (which commits to the action and its
// parameters), the approver's fingerprint, and the request nonce. That binding is
// what makes the approval un-replayable: an approval of "scuttle room=ops" cannot
// be reused to endorse "scuttle room=prod" (different params_hash), nor attributed
// to a different approver (their fingerprint is in the preimage), nor replayed
// against a different request instance (the nonce differs).
//
// Layout (action-approval v1):
//
//	field("netherchat/action-approval/v1")
//	  || field(request_id) || field(params_hash) || field(approver_fpr) || field(nonce)
//
// where field(b) = uint64-big-endian(len(b)) || b. Each field is length-prefixed
// so the encoding is injective. Both the approver (signer) and every verifier —
// the initiator collecting quorum and any passive observer counting it — derive
// these exact bytes, so a signature always means the same thing everywhere.
func ActionApprovalSigningBytes(requestID, paramsHash, approverFpr, nonce string) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/action-approval/v1")) // domain-separation tag
	writeField(&buf, []byte(requestID))
	writeField(&buf, []byte(paramsHash))
	writeField(&buf, []byte(approverFpr))
	writeField(&buf, []byte(nonce))
	return buf.Bytes()
}

// ActionApprovalSigningBytesV2 returns the canonical bytes covered by a
// two-person-rule approval that carries a declared electronic-signature MEANING:
// why the member endorsed the action (meaning, e.g. "approved" or "reviewed"),
// their printed name, and the UTC time. It extends the v1 preimage — same
// request/params/approver/nonce binding — with these three signed fields under a
// distinct domain tag, so the meaning is part of what is signed and cannot be
// altered after the fact. The endorser fingerprint binding is preserved, which is
// what lets the gate keep enforcing that the initiator cannot approve their own
// request.
//
// Meaning is opaque and extensible (the library ships authored/reviewed/approved/
// rejected as defaults); a consumer may declare others.
//
// Layout (action-approval v2):
//
//	field("netherchat/action-approval/v2")
//	  || field(request_id) || field(params_hash) || field(approver_fpr) || field(nonce)
//	  || field(meaning) || field(name) || field(signed_at)
func ActionApprovalSigningBytesV2(requestID, paramsHash, approverFpr, nonce, meaning, name, signedAt string) []byte {
	var buf bytes.Buffer
	writeField(&buf, []byte("netherchat/action-approval/v2")) // domain-separation tag
	writeField(&buf, []byte(requestID))
	writeField(&buf, []byte(paramsHash))
	writeField(&buf, []byte(approverFpr))
	writeField(&buf, []byte(nonce))
	writeField(&buf, []byte(meaning))
	writeField(&buf, []byte(name))
	writeField(&buf, []byte(signedAt))
	return buf.Bytes()
}
