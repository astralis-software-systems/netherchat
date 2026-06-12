# NC-2 demo — the detect → respond → attest loop

This walks the full Netherchat incident loop with a real adapter and relay:

1. **Detect** — a security finding arrives at the relay through the findings adapter.
2. **Respond** — routing auto-spawns a break-glass war room and mints one-time
   join links for the responders.
3. **Attest** — the responders join, record the decisions and actions that matter,
   seal a signed record, and verify it offline.

Everything uses only the `netherchat` binaries (plus `curl`). No external
dependencies.

## Run the automated part

```sh
scripts/demo-nc2.sh
```

The script builds the binaries, starts a relay configured with one `[[source]]`
and a catch-all `[[route]]`, fires a sample finding through
`netherchat-findings-adapter`, and prints the spawned war room and its one-time
join links. That is steps 1–2, fully automated, and it proves the boundary law in
passing: the finding's `description` and `remediation` never leave the adapter.

## The attest step is deliberately human

Steps 4–6 — join the room, run `/decide` and `/action`, then `/seal` — are **not**
scripted, and that is the design, not a limitation:

> Detection raises alarms; only humans authorize actions. (The second law.)

A shell script cannot be two people exercising the cryptographic two-person seal
inside an end-to-end-encrypted room — and it should not be. After the script prints
the join links, two operators run, in two terminals:

```sh
# Responder 1
netherchat connect ws://127.0.0.1:3000 --room <ROOM> --name alice --invite <ALICE_TOKEN>
# Responder 2
netherchat connect ws://127.0.0.1:3000 --room <ROOM> --name bob   --invite <BOB_TOKEN>
```

Then, in the room:

```
/decide contained: bucket set private, keys rotated
/action @bob file the incident report
/seal                # alice proposes the seal
/seal                # bob co-signs; a record.json is written
```

Finally, verify the sealed record offline — the last step the script automates if a
record is present:

```sh
netherchat verify record.json
```

## The whole loop, automated, in Go

Because the in-room attest can't be shell-scripted, the **authoritative** automated
proof of the entire loop — alert → spawn → join via the minted links → decide →
action → two-party seal → offline verify — lives as a test:

```sh
go test ./tui/e2e/ -run TestNC2DetectRespondAttest -v
```

It exercises exactly what the script + the manual steps do, end to end, and asserts
the sealed record verifies with two signers.

## What this demonstrates

- **Any alert source opens a war room.** The findings adapter is thin sugar over
  the generic socket; the relay has no adapter-specific code.
- **The boundary holds.** Only metadata crossed: the finding's detail stayed at the
  source; the sealed record contains only the decisions/actions the responders
  explicitly promoted.
- **Detection can't act.** The adapter opened a room; only the humans inside it,
  under the two-person rule, sealed anything.
