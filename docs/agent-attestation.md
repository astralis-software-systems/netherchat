# Agent-Decision Attestation (NC-W1 … NC-W3)

Netherchat is a generic **attestation layer for agentic tools**. It turns *"an AI
produced this"* into *"an AI drafted it, a named human approved it, here's the signed,
offline-verifiable record."* No product names, no special-casing any harness — any
agent connects through the same generic signal shape.

> An agent **proposes**. A named human **approves** under the Two-Person Rule. The
> result **seals** into a hash-chained, signed record that `netherchat verify`
> validates from a machine that was never in the room.

---

## The honest boundary statement

> The record stores the artifact **hash** and the approver's **identity**. The
> artifact **content never enters Netherchat** — not a proposal, not an approval, not
> the relay, not any log. The record is verifiable offline with `netherchat verify`.

`artifact_hash` (hex SHA-256) is the only representation of the artifact that ever
crosses. This is structural, not a convention: the proposal, the approval, and the
`artifact` record entry have a field for the hash and no field for content.

---

## The two laws this feature exists to honor

1. **Detection raises alarms; only humans authorize.** An agent event can open a room
   and seed a proposal. It can never approve, seal, or execute.
2. **An agent can never self-approve.** The proposer's fingerprint is recorded as
   `proposer_fpr`; an approval whose fingerprint equals it is refused outright and
   never counted toward quorum. This holds whether the proposal came from `/propose`
   in the TUI or from the agent adapter — see [the self-approval guard](#the-agent-self-approval-guard).

---

## The `artifact` record kind

Approval produces a first-class sealed-record entry (`kind = "artifact"`). Its `Body`
is structured metadata, covered by the entry's Ed25519 signature like any other entry:

```json
{
  "source":        "requirements-agent",
  "artifact_ref":  "Q3-requirements",
  "artifact_hash": "<hex SHA-256 of the content — never the content>",
  "approver_fpr":  "SHA256:…",
  "proposed_at":   "2026-06-12T10:00:00Z",
  "approved_at":   "2026-06-12T10:03:00Z"
}
```

The entry is authored and signed by the approving human, so its signature *proves*
that human signed off on this exact artifact hash. It hash-chains with every other
decision/action/note, and `netherchat verify` checks the whole chain.

---

## Flow A — in the TUI (`/propose`)

Inside an E2E room:

```
/propose --source requirements-agent --ref Q3-requirements --hash <sha256> --summary "draft for review"
```

Broadcasts to every member:

```
📋 Artifact proposed by requirements-agent: Q3-requirements
   Hash: <first16>...
   Approve with: /approve-artifact <proposal-id>
```

A named human (a **different** identity from the proposer) approves:

```
/approve-artifact <proposal-id>
```

- With `[action.artifact] quorum = 1`, one human approval seals the entry.
- With `quorum = 2`, two **independent** humans must approve.
- `/reject-artifact <proposal-id> [reason]` discards the proposal — no record entry.
- A proposal that is not approved within **300s** expires.

Then `/seal` collects co-signatures and writes `record.json` + `minutes.md`.

## Flow B — from an agent (the adapter)

`netherchat-agent-adapter` (NC-W2) translates agent lifecycle events into the generic
NC-1 alert and POSTs them to the relay — exactly like every other inbound connector,
no new core. Event kinds: `artifact_produced`, `sensitive_ingest`, `decision_proposed`,
`anomaly_detected`.

```sh
# one event
netherchat-agent-adapter --event event.json --server https://relay --source my-agent --token "$TOK"
# pipe mode (ndjson)
my-agent | netherchat-agent-adapter --server https://relay --source my-agent --token "$TOK"
```

Input shape (note: there is **no content field**):

```json
{
  "event_id":     "evt-1",
  "severity":     "critical|high|medium|low|info",
  "kind":         "artifact_produced|sensitive_ingest|decision_proposed|anomaly_detected",
  "source":       "my-agent",
  "artifact_ref": "Q3-requirements",
  "artifact_hash":"<sha256 of the artifact — never the content>",
  "summary":      "one-line description",
  "ts":           "2026-06-12T10:00:00Z"
}
```

Translation to NC-1: `source/severity/kind` pass through; `summary` is capped at 200
chars and gains a `[hash: <first8>]` tag when an artifact hash is present; `ref =
event_id`. When an `artifact_produced` event spawns a room, the adapter prints the
exact `netherchat propose …` command that seeds the human-approval flow.

Headless propose/approve (used by the demo and CI):

```sh
netherchat propose          --room review --source my-agent --ref Q3-requirements --hash <sha256> --server ws://…
netherchat approve-artifact --room review --identity ./alice.json --seal --out record.json --server ws://…
```

---

## The agent self-approval guard

This is the non-negotiable control. When a proposal is created, the proposer's
fingerprint is bound into the proposal (`proposer_fpr`, verified against the signed
sender). During approval counting:

- `/approve-artifact` by the proposer is refused with an error.
- An approval frame whose `approver_fpr == proposer_fpr` is dropped and never counted.

So an agent can never manufacture its own approval, even if it forges frames: a human
identity, distinct from the proposer, must sign. With `quorum = 2`, two distinct human
identities are required. The guard is tested explicitly (`TestSelfApprovalRejected`).

---

## The structured event stream (`tail --json`)

`netherchat tail <room> --json` emits metadata-only events for the whole loop:

```json
{"v":1,"type":"artifact_proposed","room":"review","actor":"requirements-agent","fpr":"SHA256:…","proposal_id":"…","artifact_ref":"Q3-requirements","artifact_hash":"…"}
{"v":1,"type":"artifact_approved","room":"review","actor":"alice","fpr":"SHA256:…","proposal_id":"…","artifact_ref":"Q3-requirements","artifact_hash":"…","approver_count":1,"quorum_needed":1}
{"v":1,"type":"artifact_sealed","room":"review","proposal_id":"…","artifact_ref":"Q3-requirements","artifact_hash":"…","approvers":["SHA256:…"],"source":"requirements-agent"}
```

The artifact content never appears — only its hash.

---

## Example `netherchat.toml` for routing agent events

```toml
[[source]]
name  = "my-agent"
token = "REPLACE_ME"

# An artifact a human must review opens a war room.
[[route]]
match.source = "my-agent"
match.kind   = "artifact_produced"
action       = "break-glass"
invite       = ["alice", "bob"]
ttl          = "2h"

# One human approver is required to seal an agent-produced artifact.
[action.artifact]
quorum = 1            # 2 = two independent humans; the proposing agent never counts
```

---

## The report

`netherchat report record.json` renders any `artifact` entries as:

```
📋 AI-drafted artifact approved
   Source: requirements-agent
   Artifact: Q3-requirements
   Hash: <first16>...
   Approved by: alice (SHA256:<first16>...)
   At: 2026-06-12T10:03:00Z
```

`--executive` shows only source, ref, approver name, and timestamp — no hash, no
fingerprint — for a leadership-facing summary.

---

## Try the whole loop offline

```sh
scripts/demo-attest.sh
```

It builds the binaries, starts a blind relay, has an agent signal an artifact, a human
approve it, seals the record, verifies it (`VALID`), tampers one byte (`TAMPERED`), and
renders the executive report — with no external dependencies.
