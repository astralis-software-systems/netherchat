# Duress mode

Duress mode is Netherchat's **coercion-resistant safe response** (C2). It defends
the case the rest of the crypto cannot: an adversary who can *compel* an operator —
physically or legally — to unlock, or to open a war room, while watching.

The idea is a **second credential**. Alongside the real one, the operator arms a
*duress* credential that looks and behaves exactly like it, but quietly triggers a
predefined safe response instead of normal access — **without signaling to the
coercer that anything unusual happened.**

This document is the precise threat model: what duress mode guarantees, how, and —
just as important — what it does **not** protect against.

## The two safe responses

| Mode | What happens | When to choose it |
|---|---|---|
| `silent_scuttle` | Destroy local sensitive state — the integration ratchets the room key forward and closes the room, exactly as a normal `/scuttle` would — and emit a signed, out-of-band duress beacon, while the UI behaves benignly. | The right answer is "there is nothing here." |
| `decoy_view` | Present a benign, pre-staged decoy in place of the real state. The real material stays sealed and hidden. | The coercer expects to *see* something; show them a harmless something. |

Both also emit a **duress beacon** (below) so a trusted monitor learns of the
coercion out of band.

## The non-negotiable: the passphrase is never stored

The duress credential is **never written anywhere** — not to disk, not even as a
hashed commitment. `Arm` derives an argon2id token from the credential and a random
**in-memory** salt, then **zeroes the credential bytes**; only the derived tokens
live on, in process memory, for the lifetime of the session.

This is not an implementation shortcut — it *is* the coercion-resistance property:

> A stored commitment would be a **tell.** An adversary who inspects the disk and
> finds a `duress_hash = …` learns that duress mode exists, and simply demands the
> duress credential too. "Derived token in memory only" means there is **no on-disk
> artifact that duress mode is even in use.**

Consequences, by design:

- Duress is armed **within a live session** (e.g., at unlock time the operator
  supplies both the real and the duress credential, or the long-lived client armed
  them at startup). It does not — cannot — persist across a cold start. That is the
  point.
- Comparison is **constant-time**, and **both** tokens are always compared, so
  neither the result nor *which* credential matched leaks through timing.
- Callers pass credentials as `[]byte` (not `string`) precisely so the zeroing is
  meaningful — a Go `string` cannot be wiped.

## The duress beacon

When a duress credential is entered, the safe response emits a **signed duress
beacon**: a small, offline-verifiable attestation that travels **out of band** to a
trusted monitor — deliberately **not** across the relay the coercer can observe.

- **Signed with the actor's own Ed25519 identity key**, so the monitor can
  *attribute* it, not merely receive an anonymous ping that anyone could forge.
- **Metadata only**: actor fingerprint, mode, an optional non-sensitive context
  label, a timestamp, and an anti-replay nonce. It never carries room content or
  the credential. (The boundary law holds here too.)
- **Offline-verifiable** with `netherchat duress verify` — it needs nothing but the
  beacon file. The embedded public key must hash to the claimed fingerprint, and
  the signature is checked over a domain-separated preimage
  (`netherchat/duress-beacon/v1`), so it can never be confused with a
  message/record/seal signature.

## What it defends against — and what it does not

**Defends against:**

- A coercer who forces an unlock/open and *watches the screen*: the duress path can
  be made to look identical to a normal one, and quietly destroys state or shows a
  decoy.
- A coercer who later *inspects the disk*: there is no artifact that duress mode
  exists or was used.
- A forged "I'm under duress" alarm: the beacon is identity-signed, so a monitor
  trusts attribution, not just receipt.

**Does NOT defend against (be honest about these):**

- A coercer who already **holds your real credential** — duress mode adds a safe
  *alternative*, it does not protect a compromised real secret.
- **Rubber-hose escalation** if the adversary knows duress mode exists *and*
  demands proof you did not use it. The defense is plausibility (no on-disk tell),
  not magic.
- **Observation of side effects the integrator leaks.** Indistinguishability is the
  **embedding application's responsibility** (see below). The primitive gives you
  the classification and the beacon; it cannot stop a UI that prints "DURESS!".
- **Out-of-band delivery of the beacon.** This package *produces* a signed beacon;
  getting it to a monitor over a channel the coercer cannot see or block is the
  operator's deployment problem.

## Building blocks (`netherchat duress`)

```sh
# Prove the whole path works — no input, no I/O, throwaway secrets + ephemeral key.
netherchat duress selftest --mode silent_scuttle

# Emit a signed, out-of-band duress beacon from your identity.
netherchat duress beacon --mode silent_scuttle --context north-site --out beacon.json

# Verify a beacon offline (needs nothing but the file).
netherchat duress verify beacon.json

# Classify one unlock attempt. Reads three lines from stdin:
#   <real-credential> <duress-credential> <attempt>
# Signals via exit code: 0 normal, 10 duress, 3 reject. Nothing is persisted.
printf 'real\nduress\nduress\n' | netherchat duress check --quiet --mode decoy_view ; echo $?
```

`check` is a **scriptable primitive / demonstration**, not the whole feature. For
genuine coercion resistance, the embedding flow must make the duress path *look
identical* to a normal one — pass `--quiet` and branch only on the exit code, so a
coercer watching the terminal sees nothing distinguishing. The real integration
target is the `duress.Guard` primitive embedded in a long-lived session, where
there is no separate exit code to observe at all.

## Invariants upheld

- **Server-blind relay.** All of this lives client-side under `tui/`; the relay
  neither links nor knows about duress mode. The beacon never rides the relay.
- **Zero telemetry.** The package opens no network connections of its own. Emitting
  a beacon produces bytes for *you* to deliver over a channel of your choosing.
- **Pure-Go, `CGO_ENABLED=0`.** argon2id + Ed25519 are pure-Go; no new heavy deps.
- **Offline-verifiable.** A duress beacon verifies with nothing but the file, like
  every other Netherchat attestation.
