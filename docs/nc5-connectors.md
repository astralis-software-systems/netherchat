# NC-5 connectors — Tier 2 expansions

NC-5 broadens connector coverage across the ops toolchain. Every adapter here is a
**thin client of mechanisms that already exist** — the NC-1 generic ingress socket
(`POST /api/v1/alert`) for inbound, and the two-way bridge (join as a decrypting
member) for outbound. No new core mechanism was added; removing any adapter removes
no core functionality.

Five deliverables:

| # | Adapter | Binaries | Direction | `kind` |
|---|---|---|---|---|
| 1 | Slack | `netherchat-slack-notify`, `netherchat-slack-bot` | outbound notify + inbound initiate | `slack-initiate` |
| 2 | Prometheus Alertmanager | `netherchat-alertmanager` | inbound | `infra-alert` |
| 3 | PagerDuty / Opsgenie | `netherchat-paging` | inbound | `page` |
| 4 | CI/CD (GitHub Actions / GitLab) | `netherchat-cicd` | inbound (webhook or CLI) | `ci-failure`, `ci-resolved` |
| 5 | SIEM outbound | `netherchat-siem-out` | outbound | — (metadata events) |

---

## The boundary law (every adapter, no exceptions)

> Only metadata, signals, and signed attestations cross the boundary. Raw content and
> the ephemeral E2E discussion never do.

For every adapter below, the guarantee is **structural, not a convention**:

- **Inbound** adapters can only populate the seven generic alert fields
  (`source · severity · kind · summary · ref · ts · signature`). There is no field
  for raw content, so a description, a log line, or a commit message has nowhere to
  go. `summary` is capped at 200 characters.
- **Outbound** adapters (`slack-notify`, `siem-out`) join the room as decrypting
  members but map **only event metadata** into a fixed shape (a Block Kit message of
  pointers, or a six-field metadata event). The seal mapping uses the chain head hash
  and signer count — never the sealed decisions.

> **Second law.** An inbound adapter can POST an alert / open a room; it can never
> approve, seal, or execute. Those are human, cryptographic actions inside the E2E
> war room. Detection rings the bell; people decide and act.

Each adapter ships a **boundary law test** (`go test ./cmd/netherchat-<adapter>/...`,
`go test ./slack/...`, `go test ./siemout/...`) that fails the build if a raw field
ever leaks.

---

## 1. Slack — notify + initiate

Slack's role mirrors Teams (NC-3) exactly, for Slack-native orgs. Two surfaces.

### Outbound notify — `netherchat-slack-notify`

Joins a room as a decrypting member and posts a Block Kit message on **open / seal /
scuttle** to a Slack [incoming webhook](https://api.slack.com/messaging/webhooks).

```sh
netherchat-slack-notify --room ops --webhook "$SLACK_WEBHOOK" \
  --on open,seal,scuttle --server wss://relay.example.com
```

> **Slack sees:** who opened the room, severity, source, a one-time join link, and (on
> seal) a record hash; (on scuttle) the reason and a receipt hash.
> **Slack never sees:** message content, decisions, or the room transcript.

Config (`netherchat-slack.toml`): `room`, `webhook_url`, `on`, `server`, `name`,
`identity`.

### Inbound initiate — `netherchat-slack-bot`

Receives a Slack [slash command](https://api.slack.com/interactivity/slash-commands),
verifies Slack's **v0 request signature** (`HMAC-SHA256` over `v0:<ts>:<body>`, with a
5-minute replay window), opens a war room via NC-1, and replies with an **ephemeral**
join link visible only to the invoker.

```
/netherchat sev1 database connection pool exhausted
```

maps `sev1→critical, sev2→high, sev3→medium, incident→high, drill→low`, forwarding
only the parsed severity + a ≤200-char summary (and Slack's opaque `trigger_id` as
`ref`). The invoking user, channel, and team are never forwarded.

Config (`netherchat-slack-bot.toml`): `listen`, `server`, `source`, `token`,
`slack_signing_secret`, `default_ttl`, `default_invitees`.

Relay config — a source plus a route:

```toml
[[source]]
name  = "slack-bot"
token = "REPLACE_ME"

[[route]]
match = { source = "slack-bot" }
action = "break-glass"
invite = ["@alice", "@bob"]
room_prefix = "inc"
ttl = "2h"
```

---

## 2. Prometheus Alertmanager — `netherchat-alertmanager`

An HTTP server you point an Alertmanager
[webhook receiver](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)
at. Only **firing** alerts cross; resolved alerts are the all-clear and never open a
room.

```sh
netherchat-alertmanager --listen :8081 \
  --server https://relay.example.com --source alertmanager --token "$TOKEN" --min-severity high
```

Translation per firing alert: `kind = infra-alert`,
`severity` from the `severity` label (`critical→critical, warning→high, info→low`),
`summary = "<alertname> on <instance>: <annotations.summary>"` (≤200 chars),
`ref = "<alertname>_<startsAt>"`, `ts` from `startsAt`. **`annotations.description`
is never read.**

Config (`netherchat-alertmanager.toml`): `listen`, `server`, `source`, `token`,
`min_severity`.

```yaml
# alertmanager.yml
receivers:
  - name: netherchat
    webhook_configs:
      - url: http://<adapter-host>:8081/
```

```toml
[[source]]
name  = "alertmanager"
token = "REPLACE_ME"

[[route]]
match = { source = "alertmanager", severity = "high|critical" }
action = "break-glass"
invite = ["@sre-oncall"]
room_prefix = "infra"
ttl = "6h"
```

---

## 3. PagerDuty / Opsgenie — `netherchat-paging`

One binary, `--pager pd|opsgenie`. When a page fires, a sealed-record war room opens
alongside it (it complements paging, it does not replace it).

```sh
netherchat-paging --listen :8082 --server https://relay.example.com \
  --source paging --token "$TOKEN" --pager pd
```

**PagerDuty** (v3 webhook): only `incident.triggered` is forwarded.
`severity` from urgency (`high→critical, low→medium`), `summary = title` (≤200),
`ref = data.id`, `kind = page`. Acknowledge/resolve never cross.

**Opsgenie**: only the `Create` action is forwarded.
`severity` from priority (`P1→critical, P2→high, P3→medium, P4/P5→low`),
`summary = alert.message` (≤200), `ref = alert.alertId`, `kind = page`.

Config (`netherchat-paging.toml`): `listen`, `server`, `source`, `token`, `pager`,
`min_severity`.

```toml
[[source]]
name  = "paging"
token = "REPLACE_ME"

[[route]]
match = { source = "paging", severity = "critical" }
action = "break-glass"
invite = ["@incident-commander", "@sre-oncall"]
room_prefix = "page"
ttl = "4h"
```

---

## 4. CI/CD — `netherchat-cicd` (B3 generalized)

This is **B3** — the CI ephemeral war room — built directly on the NC-1 socket. There
is no standalone B3 binary; this is it. A failed pipeline opens a short-TTL war room;
a later passing re-run posts a `ci-resolved` alert a route can use to auto-scuttle the
room.

Translation (failed): `kind = ci-failure`, `severity = high`,
`summary = "<job> failed on <repo>@<commit-short>"` (≤200), `ref = run_id`.
Translation (passed): `kind = ci-resolved`, `severity = info`,
`summary = "<job> passed on <repo>@<commit-short>"`. **No log output ever crosses.**

### Mode A — webhook server

```sh
# GitHub Actions (validates X-Hub-Signature-256)
netherchat-cicd --ci github --listen :8083 --server https://relay.example.com \
  --source ci --token "$TOKEN" --github-secret "$GH_WEBHOOK_SECRET"

# GitLab (validates X-Gitlab-Token, constant-time)
netherchat-cicd --ci gitlab --listen :8083 --server https://relay.example.com \
  --source ci --token "$TOKEN" --gitlab-token "$GL_WEBHOOK_TOKEN"
```

GitHub fires on `workflow_run` **completed** with conclusion `failure` (→ open) or
`success` (→ resolve). GitLab fires on a Pipeline Hook with status `failed` / `success`.

### Mode B — CLI step (run inside the pipeline)

```sh
netherchat-cicd --ci cli --server https://relay.example.com --source ci --token "$TOKEN" \
  --status failed --job "build" --run-id "$GITHUB_RUN_ID" \
  --repo "$GITHUB_REPOSITORY" --commit "$GITHUB_SHA"
```

Config (`netherchat-cicd.toml`): `listen`, `server`, `source`, `token`, `ci`,
`github_secret`, `gitlab_token`, `default_ttl` (informational — the relay route sets
the room's real TTL).

```toml
[[source]]
name  = "ci"
token = "REPLACE_ME"

# Failure opens a short-TTL room.
[[route]]
match = { source = "ci", kind = "ci-failure" }
action = "break-glass"
invite = ["@dev-oncall"]
room_prefix = "ci"
ttl = "1h"

# A passing re-run scuttles it.
[[route]]
match = { source = "ci", kind = "ci-resolved" }
action = "scuttle"
```

---

## 5. SIEM outbound — `netherchat-siem-out`

The outbound twin of the NC-2 inbound SIEM adapter: it joins a room as a decrypting
member and streams **metadata-only** lifecycle events back to a SIEM for one unified,
tamper-evident audit trail.

```sh
netherchat-siem-out --room ops --siem splunk \
  --siem-url https://splunk.example.com:8088 --siem-token "$HEC_TOKEN" \
  --server wss://relay.example.com
```

The only shape that crosses is a fixed six-field event — there is no field for content:

```json
{
  "netherchat_event": "join|leave|ack|vanish|seal|scuttle|clock_start|clock_stop|action_request|action_executed|action_vetoed",
  "room": "inc-1",
  "actor": "alice",
  "fpr": "SHA256:...",
  "ts": "2026-06-12T10:00:00Z",
  "room_epoch": 3
}
```

Supported targets:

- **Splunk HEC** — `POST <siem_url>/services/collector/event`,
  `Authorization: Splunk <token>`, newline-delimited `{"time":<unix>,"event":{…}}`.
- **Microsoft Sentinel** — `POST <siem_url>/api/logs?api-version=2016-04-01`,
  `Authorization: SharedKey <workspace>:<sig>`, JSON array.
- **Generic** — `POST <siem_url>`, optional `Authorization: Bearer <token>`, JSON array.

Batching is in-memory: it flushes when the buffer reaches `batch_size` (default 100)
**or** every `flush_interval` (default 5s), whichever comes first. There is **no
on-disk queue** — a process exit loses unflushed events, by design.

Config (`netherchat-siem-out.toml`): `room`, `server`, `name`, `identity`, `siem`,
`siem_url`, `siem_token`, `batch_size`, `flush_interval`.

> **The SIEM sees:** who did what and when (event type, actor, fingerprint, room,
> timestamp, epoch). **The SIEM never sees:** message bodies, decision text, tags,
> reasons — any content.

---

## Invariants held across all five

- **Server-blind relay** — the crypto stays unreachable from the server binary; these
  adapters are arms-length clients of the public HTTP / bridge contracts.
- **Zero telemetry / persistence** — every destination is config-driven and explicit;
  an empty destination is rejected (no default external endpoint anywhere).
- **Pure-Go, `CGO_ENABLED=0`, minimal deps** — plain HTTPS / stdlib only; no vendor SDKs.
- **Boundary law + second law** — tested per adapter; metadata/attestations only,
  detection can't act.
