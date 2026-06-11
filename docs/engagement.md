# Engagement-in-a-box

`netherchat engagement` generates a **turnkey, self-contained deployment package**
a security consultant can stand up per client, and rolls the resulting sealed
records into a single, offline-verifiable **close report** at the end.

It exists because standing up secure coordination for a new engagement — a relay,
rooms, identities, trust pins, the Two-Person Rule, and a reporting story — is the
same checklist every time. This packages that checklist into one command, while
keeping every Netherchat invariant intact: the relay stays blind, nothing phones
home, and the records that matter stay cryptographically verifiable.

> The language here is deliberately industry-neutral. "Engagement", "client", and
> "consultant" are roles, not a vertical. The same package serves incident
> response, security operations, audit, or any sensitive, time-boxed coordination.

## `netherchat engagement init`

```sh
netherchat engagement init \
  --name acme-q3 \
  --client "Acme Corp" \
  --consultant alice --consultant bob \
  --room ops --room findings \
  --quorum 2
```

This creates `./acme-q3/`:

```
acme-q3/
├── netherchat.toml      # relay config: rooms, trust pins, action quorums
├── docker-compose.yml   # the blind relay, ready to `docker compose up -d`
├── identities/
│   ├── identity-alice.json   # Ed25519 private identity (0600)
│   └── identity-bob.json
├── trust-pins.txt       # handle → fingerprint, for out-of-band verification
├── records/             # drop sealed records here before closing
├── engagement.json      # machine-readable manifest (no secrets)
└── README.md            # deploy / distribute / close checklist
```

What it provisions:

- **Rooms** — each is invite-only, has an inbound webhook with a generated token,
  a hard `ttl`, and a `scuttle.idle_after` so an abandoned room burns its own keys.
- **Trust pins** — one `[[trust]]` entry per consultant, pinned to the fingerprint
  of the identity generated for them. Verify these **out of band** (read them aloud)
  before trusting; a pin is only as good as the channel you confirmed it over.
- **Action quorums** — `[action.scuttle]` and `[action.break_glass]` are set to
  `--quorum` (default 2): the Two-Person Rule, enforced client-side and
  cryptographically. The relay only ever sees ciphertext.
- **Per-consultant identities** — one Ed25519 identity file each, written `0600`.

### ⚠️ The identity files are private keys

Each `identities/identity-<handle>.json` contains a **private key**. There is **no
escrow and no recovery** — that is the design. Deliver each file to its owner over
a secure channel and remove your copy. Better still, have each consultant **bring
their own key** and replace the generated pin in `netherchat.toml` with theirs;
then no private key is ever generated centrally.

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--name` | *(required)* | engagement name; also the package directory |
| `--client` | — | optional client/organization label |
| `--consultant` | *(≥1 required)* | consultant handle; repeatable or comma-separated |
| `--room` | `ops,findings` | room to provision; repeatable or comma-separated |
| `--out` | `.` | parent directory for the package |
| `--addr` | `:3000` | relay listen address |
| `--image` | `salkreiner/netherchat:latest` | relay container image |
| `--quorum` | `2` | Two-Person-Rule quorum for scuttle/break-glass |
| `--ttl` | `168h` | hard room lifetime |
| `--idle` | `2h` | room scuttle `idle_after` |

`init` refuses to overwrite an existing directory, so it never clobbers identity
files.

## Deploying the package

```sh
cd acme-q3
docker compose up -d                      # start the blind relay

netherchat connect ws://RELAY_HOST:3000 \
  --identity identities/identity-alice.json \
  --config netherchat.toml \
  --room ops
```

## `netherchat engagement close`

When the work is done, drop each war room's sealed record (`/seal` → `record.json`)
into `records/`, then:

```sh
netherchat engagement close acme-q3
# wrote acme-q3/close-report.md — 3 of 3 sealed record(s) verified offline
```

The close report:

- **re-verifies every record offline** — the same hash-chain + signature check as
  `netherchat verify`, run independently of any server;
- lists each record's room, seal time, entry count, and co-signers in a summary
  table, flagging any record that does **not** verify;
- reproduces the sealed **decisions and actions** per record.

It contains **no message content** — only what was explicitly sealed in-room. The
ephemeral discussion was never recorded in the first place, so there is nothing to
leak.

Use `--out <path>` to write the report elsewhere (default `<dir>/close-report.md`).

## How this keeps the invariants

- **Server-blind relay.** The package only configures the relay; it never asks it
  to read content. Identities and keys live in the package and on consultants'
  machines, never on the relay.
- **Zero telemetry.** Generation and close are local file operations. Nothing is
  sent anywhere.
- **Offline-verifiable records.** The close report's verification is the same
  offline check as `netherchat verify`; a reader can re-run it on any machine.
- **Pure-Go, `CGO_ENABLED=0`.** The command is part of the standard `netherchat`
  binary — no new heavy dependencies.
