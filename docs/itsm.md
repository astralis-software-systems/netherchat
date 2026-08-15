# ITSM connector — ServiceNow & Jira (NC-4)

`netherchat-itsm` is the outbound **system-of-record** integration: when an
incident room is sealed, the signed, verifiable record is attached to the incident
ticket as the authoritative artifact, and a metadata work note is added. It is a
bridge daemon — it joins the room as a decrypting member, watches for the seal
event, and files the record to ServiceNow or Jira over plain REST (no SDK).

## The boundary — read this first

> **The ITSM ticket receives:** the sealed record JSON (the same artifact
> `netherchat verify` validates), the signer fingerprints and count, the head hash,
> and the elapsed time.
>
> **The ticket never receives:** message content, decisions text outside the sealed
> record, the room transcript, or anything not explicitly in the sealed record.

The attachment is the marshaled sealed record, byte-for-byte — nothing is appended.
Its entries are the decisions and actions that were **deliberately promoted and
sealed** in the room (`/decide`, `/action`, `/mark`); the ephemeral chat was never
in the record and never crosses. The human **work note / comment** is metadata
only — signer count, head hash, elapsed time, the verify command — never decision
text. A boundary-law test enforces both halves and fails the build otherwise.

The **second law** holds: the daemon files an attestation on seal; it never
approves, seals, or executes anything inside the room.

## Setup

Build the binary from source — releases and the Docker image ship only
`netherchat` and `netherchat-server`. With Go 1.26+:

```sh
go build -o bin/ ./cmd/netherchat-itsm
```

(`go build -o bin/ ./cmd/...`, or `just build`, builds every binary in the repo.)

### ServiceNow

```sh
netherchat-itsm \
  --room ops \
  --itsm servicenow \
  --ticket INC0010001 \
  --itsm-url https://instance.service-now.com \
  --itsm-user admin \
  --itsm-token "$SN_TOKEN" \
  --server ws://localhost:3000
```

- Attachment → `POST /api/now/table/sys_attachment` (multipart: `table_name=incident`,
  `table_sys_id=<ticket>`, `file_name`, `content_type=application/json`, `file`).
- Work note → `PATCH /api/now/table/incident/<ticket>` with `{"work_notes": "..."}`.

### Jira

```sh
netherchat-itsm \
  --room ops \
  --itsm jira \
  --ticket INC-1234 \
  --itsm-url https://company.atlassian.net \
  --itsm-user user@company.com \
  --itsm-token "$JIRA_TOKEN" \
  --server ws://localhost:3000
```

- Attachment → `POST /rest/api/3/issue/<ticket>/attachments` (multipart `file`,
  header `X-Atlassian-Token: no-check`).
- Comment → `POST /rest/api/3/issue/<ticket>/comment` with an ADF body.

Both authenticate with HTTP Basic (`--itsm-user` / `--itsm-token`). Config files:
`netherchat-itsm-servicenow.toml.example` and `netherchat-itsm-jira.toml.example`.

## The work note

Identical text for both backends:

```
Incident record sealed by 2 member(s).
Head hash: 0123456789abcdef...
Duration: 18m4s
Verify: netherchat verify netherchat-record-ops-1718185200.json
Provenance: X-Netherchat-Sig present
```

## Verifying the attached record offline

Download the attachment from the ticket and run:

```sh
netherchat verify netherchat-record-<room>-<ts>.json
```

It checks the hash chain, every entry signature, the head, and every seal
signature — needing nothing but the file. The head hash in the work note lets you
cross-check you are verifying the same record the ticket references.

## Provenance headers (and how to check them)

Every ITSM request carries Ed25519 provenance, mirroring the two-way bridge:

| Header | Value |
|---|---|
| `X-Netherchat-Room` | the room name |
| `X-Netherchat-Fpr` | the sealer's fingerprint (`SHA256:…`) |
| `X-Netherchat-Sig` | the sealer's base64 Ed25519 signature over the sealed head |
| `X-Netherchat-Ts` | the sealed-at timestamp (RFC3339) |

`X-Netherchat-Sig` is the sealer's own seal signature — the same one inside the
record. To check it, take the attached record, look up the sealer's public key in
its `signer_keys` (confirming it hashes to `X-Netherchat-Fpr`), and verify the
signature over the domain-separated head preimage. Equivalently, `netherchat verify`
already validates that signature as part of the record, so a verifying record is a
verifying provenance header.

## If attachment fails

Delivery is **in-memory only**, with a bounded retry (1s/2s/4s) on transport errors
and `5xx`. There is **no on-disk queue** — the same ephemerality guarantee as the
bridge. If every attempt fails, the daemon prints the full sealed record JSON to
**stdout**, prefixed with `ATTACH FAILED`, so an operator can attach it manually.
That stdout dump is the only fallback persistence, and it is an operator action —
never an automatic write to disk.

## Invariants

- Server-blind relay untouched (this is a client/edge daemon; the relay imports
  none of it). Zero telemetry; no on-disk queue.
- Pure-Go, `CGO_ENABLED=0`, plain REST — no ServiceNow or Jira SDK.
- Only the deliberately-sealed record crosses; the work note is metadata-only; the
  attached record verifies offline; provenance is present and checkable.
