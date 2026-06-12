# Inbound connectors (NC-2)

Netherchat's inbound connectors are **thin typed adapters** over the generic signed
ingress socket (`POST /api/v1/alert`, NC-1). Each one takes the output of a source
tool, translates it into the single generic alert shape, and POSTs it to a relay.
A matching `[[route]]` then spawns a break-glass war room and invites the
responders.

Three ship in NC-2:

| Adapter | Binary | Source tools | `kind` |
|---|---|---|---|
| Security findings | `netherchat-findings-adapter` | any tool that produces security findings — cloud scanners, CSPM, vulnerability scanners, infra-audit, pen-test reporters | `security-finding` |
| AI egress signal | `netherchat-egress-adapter` | any tool that monitors AI/LLM prompt egress and detects sensitive data | `egress-signal` |
| SIEM | `netherchat-siem-adapter` | Splunk or Microsoft Sentinel webhook alerts | `siem-alert` |

They are **arms-length**: an adapter is a small standalone binary that depends only
on the relay's public HTTP contract. Removing an adapter removes no core
functionality, and the relay has no adapter-specific code.

---

## The boundary law (what crosses, what never does)

> Only metadata, signals, and signed attestations cross the boundary. Raw regulated
> content and the ephemeral E2E discussion never do.

Every adapter emits **only** the seven generic alert fields:

```
source · severity · kind · summary · ref · ts · signature
```

`summary` is capped at 200 characters and is built only from labels and
identifiers. The detail a source tool holds — a finding's `description` and
`remediation`, the actual content an egress monitor scrubbed, a SIEM's raw log
lines and `alertContext` — is **never read into the alert** and therefore cannot
cross. This is structural, not a convention: the adapters share one `Alert` type
that has no field for raw content, so there is nowhere to put it.

> **Second law.** An adapter can POST an alert; it can never approve, seal, or
> execute. Those are human, cryptographic actions inside the E2E war room. A
> detection source rings the bell; people decide and act.

### Verifying the boundary yourself

Point an adapter at any HTTP listener and inspect the body it POSTs:

```sh
# A one-liner capture server (or use `nc -l`, mitmproxy, etc.)
python3 -c 'import http.server;http.server.HTTPServer(("",9999),type("H",(http.server.BaseHTTPRequestHandler,),{"do_POST":lambda s:(s.send_response(200),s.end_headers(),print(s.rfile.read(int(s.headers["content-length"]))))}))().serve_forever()'

netherchat-findings-adapter --finding finding.json --server http://localhost:9999 --source x --token t
```

The printed body contains only the seven fields above — no `description`, no
`remediation`. Each adapter also ships a **boundary law test** (`go test
./cmd/netherchat-...-adapter/`) that asserts exactly this and fails the build if a
raw field ever leaks.

---

## Relay setup (shared by all adapters)

Register each adapter as a `[[source]]` and add a `[[route]]` that decides which
alerts open a war room. Both live in `netherchat.toml` (see `docs/ingress.md`).

```toml
# Authenticate the adapter. Use a token OR an hmac_secret (or both).
[[source]]
name = "my-scanner"
token = "REPLACE_ME"
# hmac_secret = "REPLACE_ME"   # alternative: signed alerts, tamper-evident in transit
rate_per_minute = 30
spawn_per_hour  = 10

# Open a war room when a high/critical finding arrives.
[[route]]
match = { source = "my-scanner", severity = "high" }   # values may be regex, e.g. "high|critical"
action = "break-glass"
invite = ["@alice", "@bob"]
room_prefix = "inc"
ttl = "12h"
```

Routes match on the generic fields (`source`, `severity`, `kind`, `summary`,
`ref`), so one relay config serves every adapter.

---

## Adapter 1 — security findings

```sh
# Single finding from a file
netherchat-findings-adapter --finding finding.json \
  --server https://relay.example.com --source my-scanner --token "$TOKEN"

# Pipe mode: one finding per line (ndjson)
my-scanner --json | netherchat-findings-adapter \
  --server https://relay.example.com --source my-scanner --token "$TOKEN"
```

Input shape (any tool that emits — or can be wrapped to emit — this connects with
no core changes):

```json
{
  "finding_id":  "f-001",
  "severity":    "critical|high|medium|low|info",
  "check_id":    "CIS-1.20",
  "resource":    "arn:aws:s3:::public-bucket",
  "region":      "us-east-1",
  "title":       "S3 bucket allows public read",
  "description": "long detail — NOT forwarded",
  "remediation": "fix steps — NOT forwarded",
  "ts":          "2026-06-12T10:00:00Z"
}
```

Translation: `kind = security-finding`, `summary = "<check_id>: <title>
(<resource>)"` (≤200 chars), `ref = finding_id`, `severity` passed through,
`ts` parsed. **`description` and `remediation` never cross.**

Config (`netherchat-findings.toml`):

```toml
server       = "https://relay.example.com"
source       = "my-scanner"
token        = "REPLACE_ME"
min_severity = "high"
```

---

## Adapter 2 — AI egress signal

```sh
netherchat-egress-adapter --event event.json \
  --server https://relay.example.com --source ai-egress-monitor --token "$TOKEN"
```

Input shape:

```json
{
  "event_id":    "e-001",
  "severity":    "critical|high|medium|low",
  "event_type":  "credential_leak|pii_leak|proprietary_leak|sensitive_data",
  "tool":        "the LLM tool being monitored",
  "scrub_count": 3,
  "categories":  ["api_key", "email"],
  "ts":          "2026-06-12T10:00:00Z"
}
```

Translation: `kind = egress-signal`, `summary = "<event_type> detected in <tool>:
<scrub_count> items (<categories>)"` (≤200 chars), `ref = event_id`. **The actual
detected content is never in the signal and never forwarded** — only the count and
category labels.

Config (`netherchat-egress.toml`): same fields as findings, with
`source = "ai-egress-monitor"`.

---

## Adapter 3 — SIEM (Splunk + Sentinel)

Runs as a small HTTP server the SIEM points its alert action / playbook at.

```sh
netherchat-siem-adapter --listen :8080 \
  --server https://relay.example.com --source siem --token "$TOKEN" --siem splunk
```

Point Splunk's webhook alert action, or a Sentinel automation/Logic App, at
`http://<adapter-host>:8080/`.

**Splunk** → `summary = "<search_name> triggered on <host>"`,
`ref = "<search_name>_<_time>"`, `ts` from `_time`. Raw log content
(`result._raw`, …) is never read.

**Sentinel** → `summary = "<alertRule> triggered"`,
`ref = "<alertRule>_<firedDateTime>"`, `ts` from `firedDateTime`; severity maps
`Sev0→critical, Sev1→high, Sev2→medium, Sev3→low, Sev4→info`. `alertContext` is
never read.

Config (`netherchat-siem.toml`):

```toml
listen       = ":8080"
server       = "https://relay.example.com"
source       = "siem"
token        = "REPLACE_ME"
siem         = "splunk"   # or "sentinel"
min_severity = "medium"
```

---

## Authentication

Each `[[source]]` declares a `token`, an `hmac_secret`, or both (the relay requires
every declared credential to pass). Adapters set them via `--token` /
`--hmac-secret` or their config file. With an HMAC secret, the adapter signs each
alert (`signature` = `HMAC-SHA256` over the domain-separated preimage), so the
alert is tamper-evident in transit. See `docs/ingress.md`.

## Common flags

| Flag | Meaning |
|---|---|
| `--server` | relay base URL |
| `--source` | registered `[[source]]` name |
| `--token` / `--hmac-secret` | per-source auth |
| `--min-severity` | drop alerts below this severity (unknown severities fail-open) |
| `--config` | TOML config file (flags override file values) |

## Connecting any tool

If your tool can emit the findings JSON above — directly or via a one-line `jq`
wrapper — it connects to Netherchat with zero core changes. The generic schema is
the contract; the adapters are just convenience. To connect something exotic, emit
the seven generic fields and POST them yourself (see `docs/ingress.md`).
