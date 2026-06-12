# Generic signed ingress socket (NC-1)

`POST /api/v1/alert` is the one endpoint every inbound connector rides. Any
registered tool — a cloud scanner, an AI-egress monitor, a SIEM — POSTs a
**schema-valid, metadata-only alert**; if it matches a `[[route]]`, the relay
spawns a break-glass war room with one-time invites and a marked-plaintext join
notice. There is no app-specific code in the core: every "integration" is just a
tool emitting this shape.

It is built on two laws:

> **The boundary law.** Only metadata, signals, and signed attestations cross.
> Raw regulated content and the ephemeral E2E discussion never do.

> **The second law.** Detection raises alarms; only humans authorize actions. An
> inbound alert can open a room and post a notice — it can **never** approve, seal,
> or execute. Those are end-to-end, client-signed, room-keyed messages a blind
> relay can never forge.

## The alert schema

JSON, **metadata only**, decoded strictly (unknown fields rejected, 64 KiB cap):

```json
{
  "source":   "scanner",        // required — must match a registered [[source]].name
  "severity": "high",           // required
  "kind":     "finding",        // required
  "summary":  "s3 bucket public", // optional, ≤ 1 KiB — a one-line description, NOT raw data
  "ref":      "CIS-1.20",       // optional, ≤ 256 B — an external ID/reference
  "ts":       1700000000,       // optional unix seconds
  "signature":"<hex>"           // required for HMAC sources (see below)
}
```

`source`, `severity`, `kind`, `ref` are capped at 256 B and `summary` at 1 KiB —
the relay must never become a channel for raw content. Anything missing a required
field, oversized, or carrying an unknown field is rejected (`400`) and spawns
nothing.

## Registering a source

Sources are config-as-code in `netherchat.toml`. A source declares a bearer
`token`, an `hmac_secret`, or **both** (every declared credential must pass —
defense in depth). A source with neither is rejected: there is no default-open
ingress.

```toml
[[source]]
name = "scanner"
token = "REPLACE_ME"        # bearer-token auth

[[source]]
name = "siem"
hmac_secret = "REPLACE_ME"  # HMAC-SHA256 signature auth
rate_per_minute = 30        # optional; default 60
spawn_per_hour  = 10        # optional; default 20
```

### Token auth

Send the token in the `X-Netherchat-Token` header (or `?token=`), compared in
constant time.

```sh
curl -X POST https://relay.example.com/api/v1/alert \
  -H "X-Netherchat-Token: $TOKEN" \
  -d '{"source":"scanner","severity":"high","kind":"finding","summary":"s3 public","ref":"CIS-1.20"}'
```

### HMAC signature auth

The `signature` field is `hex(HMAC-SHA256(hmac_secret, preimage))`, where the
preimage is the domain-separated, length-prefixed
`protocol.AlertSigningBytes(source, severity, kind, summary, ref, ts)` (tag
`netherchat/alert/v1`). The relay recomputes it and compares in constant time, so
the alert is **tamper-evident in transit** — altering any field invalidates it.

## Routing → war room

Alerts are matched by the existing `[[route]]` rules, on the flat alert fields:

```toml
[[route]]
match = { source = "scanner", severity = "high" }  # AND-ed; values may be regex
action = "break-glass"
invite = ["@alice", "@bob"]
room_prefix = "inc"
ttl = "12h"
reply_url = "https://your-system.example/incident-hook"  # optional, your own system
```

On a match the relay spawns an ephemeral, invite-only room (`inc-<8hex>`), mints a
one-time join link per invitee (returned in the response and optionally POSTed to
`reply_url`), and attaches a marked-plaintext notice. **No match is still a
success** (`{"accepted":true,"spawned":false}`) — the alert was authenticated and
accepted; it just opened no room.

### The marked-plaintext notice

The spawned room carries a one-line, metadata-only notice
(`[high] scanner/finding: s3 bucket public (ref CIS-1.20)`) delivered to each
responder **as they join**, as a plaintext `OpServerMessage` clearly marked "not
encrypted". It is ephemeral, dies with the room, and never contains raw content.

## Hardening

- **Per-source rate limit** (`rate_per_minute`, default 60) and **spawn cap**
  (`spawn_per_hour`, default 20): a token bucket each, keyed by source. Exceeding
  either returns `429` and spawns nothing.
- **Strict schema + size cap**: unknown/oversized fields rejected; 64 KiB body cap.
- **Metadata-only logging**: every rejection (unknown source, bad auth, malformed,
  capped) is logged with source/severity/kind only — never the summary.

## Invariants

The socket is server-side only (`server/internal/alert`, `protocol/alert_signing.go`
is pure); nothing imports the client crypto, so the relay stays blind and the CI
import-boundary check holds. No new outbound calls (only your own optional
`reply_url`). Pure-Go, `CGO_ENABLED=0`. The alert path can only open an invite-only
room and set a plaintext notice — it has no code path to approve, seal, or execute.
