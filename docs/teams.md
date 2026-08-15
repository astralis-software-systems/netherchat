# Microsoft Teams connector (NC-3)

Netherchat's Teams connector is the **notify / initiate** surface for the priority
enterprise messaging channel. It has two halves, both plain HTTPS — **no Teams
SDK**:

- **Outbound notify** (`netherchat-teams-notify`) — posts an Adaptive Card to a
  Teams channel when a war room **opens**, **seals**, or **scuttles**.
- **Inbound initiate** (`netherchat-teams-bot`) — lets a Teams user open a war room
  with a chat command and get back a one-time join link.

Both are built from source — releases and the Docker image ship only `netherchat`
and `netherchat-server`. With Go 1.26+:

```sh
go build -o bin/ ./cmd/netherchat-teams-notify
go build -o bin/ ./cmd/netherchat-teams-bot
```

(`go build -o bin/ ./cmd/...`, or `just build`, builds every binary in the repo.)

## The boundary — read this first

> **Teams sees:** who opened the room, the severity, a one-time join link, and (on
> seal) a record hash. Plus, on scuttle, the reason and a receipt hash.
>
> **Teams never sees:** message content, decisions, the room transcript, or
> anything discussed inside the room.

A pointer to a secure room is safe to post in Teams; the conversation it points to
is **not in Teams at all** — it stays end-to-end encrypted inside Netherchat. The
notify bridge is a full room member (it must decrypt to learn that an event
happened), but it forwards only event metadata: the seal card carries the chain
head hash and a signer count, never the sealed decisions. The initiate bot forwards
only a parsed severity and a short summary, never the Teams thread, sender, or
channel data. Each surface ships a boundary-law test that fails the build if that
is ever violated.

The **second law** holds too: the bot can *initiate* a room; it can never approve,
seal, or execute inside one. Those stay human and cryptographic, in the E2E room.

---

## Outbound notify — `netherchat-teams-notify`

A bridge daemon: it joins a room as a decrypting member and fires Teams cards on the
events you subscribe to.

### Setup

1. In Teams: **Channel → Connectors → Incoming Webhook**, name it, copy the URL.
2. Run the daemon against the room you want Teams notified about:

```sh
netherchat-teams-notify \
  --room ops \
  --webhook "https://outlook.office.com/webhook/..." \
  --on open,seal,scuttle \
  --server ws://localhost:3000 \
  --name teams-bridge
```

Or configure it with `netherchat-teams.toml` (see `netherchat-teams.toml.example`).

> Deployment note: run it in the room you want surfaced. "open" fires when an
> inbound alert opens that war room (the relay posts a marked notice the daemon
> sees); "seal"/"scuttle" fire on the in-room seal / scuttle. If the room is
> invite-only, pass `--invite <token>`.

### The cards

**open** — `⚡ War room opened: #ops`
```
Severity: high · Source: scanner
Opened by: ingress
Expires: 1h0m0s
[ Join room ]      ← Action.OpenUrl with a one-time link
```

**seal** — `🔒 Incident sealed: #inc-3f9a`
```
Sealed by: 2 member(s)
Duration: 18m4s
Record hash: 0123456789abcdef...
Verify the sealed record offline with: netherchat verify record.json
```

**scuttle** — `💨 Room scuttled: #inc-3f9a`
```
Scuttled by: alice · Reason: manual
Receipt: abcdef0123456789...
```

Each is sent as an Adaptive Card (v1.2) message — a plain JSON `http.Post` to the
incoming webhook. Cards are fire-and-forget with no on-disk queue (ephemerality is
preserved; if the daemon dies, pending cards are lost by design).

---

## Inbound initiate — `netherchat-teams-bot`

A small HTTP server that turns a Teams command into a war room.

### Setup

1. Register a `[[source]]` for the bot in the relay's `netherchat.toml`:
   ```toml
   [[source]]
   name  = "teams-bot"
   token = "REPLACE_ME"
   ```
   and a `[[route]]` deciding who is invited when the bot fires:
   ```toml
   [[route]]
   match = { source = "teams-bot" }
   action = "break-glass"
   invite = ["@alice", "@bob"]
   room_prefix = "inc"
   ttl = "2h"
   ```
2. In Teams: **Channel → Connectors → Outgoing Webhook** (or a bot), point its
   callback URL at the bot, and copy the **HMAC security token**.
3. Run the bot:

```sh
netherchat-teams-bot \
  --listen :9090 \
  --server https://relay.example.com \
  --source teams-bot \
  --token "$NC1_TOKEN" \
  --teams-secret "$TEAMS_SECRET"
```

Or configure with `netherchat-teams-bot.toml` (see the `.example`).

### Commands

| Command | Severity |
|---|---|
| `@netherchat sev1 <summary>` | critical |
| `@netherchat sev2 <summary>` | high |
| `@netherchat sev3 <summary>` | medium |
| `@netherchat incident <summary>` | high |
| `@netherchat drill <summary>` | low |

The bot verifies Teams' HMAC-SHA256 signature on every request (unsigned or
mis-signed requests get `401` and open nothing), parses the command, POSTs a
metadata-only alert to `POST /api/v1/alert`, and replies in-channel:

```
⚡ War room opened: #inc-3f9a2b71
Severity: critical
Opened by: Teams
Expires: 2h
[ Join room ]
```

The summary is truncated to 200 characters. The full Teams message thread, the
sender, and channel data are never forwarded.

---

## Verifying the boundary yourself

- Notify: point `--webhook` at a local capture server and trigger a seal; the card
  JSON contains the head hash and signer count, never a decision body.
- Bot: point `--server` at a capture server and send a command; the forwarded
  `/api/v1/alert` body contains only `{source, severity, kind, summary, ref, ts,
  signature}` — never the Teams thread.

Both are enforced by `go test ./teams/ ./cmd/netherchat-teams-notify/
./cmd/netherchat-teams-bot/`, whose boundary-law tests assert no content crosses.
