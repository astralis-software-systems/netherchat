# Seal Co-Signature Loss — Fix Plan

> **Status:** DESIGN — not yet built. This document is the only deliverable; no code
> has been changed.
>
> **Goal:** Guarantee that a verified co-signature for a sealed head is **never lost**,
> so a multi-party `/seal` produces a durable record carrying *every* participant's
> attestation — the core "multi-party, offline-provable attestation" claim the bug
> currently undercuts. Fix it client-side, mirror the codebase's own correct pattern
> where useful, and do it **without a wire/signed-bytes change**.
>
> **Repo / baseline:** `main`, HEAD `b08a567` (working tree clean at read time).
>
> **Threat model (scope-setting, read this first):** the sealed record is a
> **client-side attestation artifact** built over detached Ed25519 signatures; the relay
> is **blind by design** and never sees or assembles seals. This bug is a *correctness /
> data-loss* defect (a legitimately-produced co-signature is silently discarded), **not**
> a forgery or tamper hole — co-signatures are and remain ed25519-verified against the
> signer's identity key, and cannot be forged. The fix makes the official client retain
> and durably record every co-signature it can verify. It does **not** attempt to make
> the record *self-certify who was expected to sign* — that is a distinct, format-
> versioned capability, deliberately deferred (see §5.B and §6). Making that boundary
> explicit is part of the deliverable, not a gap in it.

---

## 1. The bug (corrected diagnosis)

The read established the defect precisely; it is restated here as settled fact, not
re-derived. The original test hypothesis ("no co-signature round exists") was **wrong**:
a round exists and runs. The defect is the round's **completion condition** and its
**one-shot write**.

### 1.1 The round that exists

`tui/client/record.go` implements a full co-signature handshake:

- **Initiate** — `sealWith` (`record.go:134`) signs the initiator's own seal over the
  head, sets `c.sealing = true`, seeds `c.sealSigs = {self: sig}`, arms
  `c.sealTimer = time.AfterFunc(sealTimeout, c.finalizeSeal)` (`record.go:194`;
  `sealTimeout = 30s`, `client.go:157`), broadcasts `OpSealRequest`, then calls
  `maybeFinalize()` (`record.go:202`).
- **Co-sign** — a peer's `/seal` reaches `sendSealAck` (`record.go:209`), which signs and
  broadcasts `OpSealAck`, then emits `EvSealAck{Self:true}` → UI prints
  **"✓ you co-signed the seal"** (`model.go:657-659`). The co-signer writes **no file**.
- **Collect** — the initiator's `onSealAck` (`record.go:256`) ed25519-verifies each ack,
  adds it to `c.sealSigs`/`c.sealKeys`/`c.sealEndorse`, and calls `maybeFinalize()`.
- **Finalize** — `finalizeSeal` (`record.go:302`) assembles the `SealedRecord`, attaches
  artifact proofs, emits `EvSealComplete` → **only** the initiator writes `record.json` +
  `minutes.md` (`model.go:664`, `writeSealedRecord` at `commands.go:991`).

### 1.2 Root cause — a racy, initiator-local completion denominator

Completion is decided by:

```
// record.go:292 (maybeFinalize)
done := c.sealing && len(c.sealSigs) >= len(c.order)   // denominator = c.order
```

`c.order` is the **initiator's local, racy membership view** — seeded from the welcome
roster and appended on `onMemberJoined` (`client.go:839-846`, `878`). It is not
authoritative, not consistent across members, and evaluated at finalize time.

### 1.3 Race 1 — immediate finalize at `order == 1`

When the co-signer's join has **not yet propagated** into the initiator's `c.order`, the
denominator is `1`. Because `c.sealSigs` already contains the initiator's own signature,
`1 >= 1` holds and `maybeFinalize` finalizes **synchronously inside `sealWith`**
(`record.go:202`) — a one-signature record is written **before any network round-trip**.
`finalizeSeal` then sets `c.sealing = false` and nils the seal maps. The co-signer's later
`OpSealAck` hits `if !c.sealing { return }` (`record.go:258`) and is **silently dropped** —
no event, no error, no re-write. This is the "written immediately" reproduction.

### 1.4 Race 2 — post-timeout late ack

Even when `order == 2`, a co-signer who acks **after** the 30 s `sealTimer` has fired is
dropped by the *same* `!c.sealing` guard. The two races converge on one post-finalize
failure: **any verified co-signature arriving after finalize is discarded.**

### 1.5 The silent-failure gaps (why the bug hid)

- **Co-signer side:** `sendSealAck` emits `EvSealAck{Self:true}` → "✓ you co-signed"
  **unconditionally after sending**, with no acknowledgement-of-acknowledgement. The
  co-signer is told success whether or not the sealer counted it. Fire-and-forget.
- **Sealer side:** `onSealAck`'s post-finalize path is a bare `return` — a dropped
  co-signature emits nothing at all.
- **`verify` side:** `SealedRecord.Verify()` checks chain linkage, head hash, and that
  **every signature present** verifies. It has **no concept of a signature that *should*
  be present**. A one-signature record is fully VALID. It counts what is there, not what
  is missing — so nothing, anywhere, flags the loss. `TestSealRoundTrip`
  (`tui/e2e/sealed_test.go`) itself *works around* the bug by waiting for
  `EvMemberJoined` before sealing "so her seal denominator is 2."

---

## 2. The enabling crypto fact — amendment is coherent

Verified by the read and central to the recommended fix:

- Seal signatures are **detached** and live **outside** the hash chain. `SealedRecord`
  holds `Entries` (the chain) + `HeadHash` **separately** from
  `Signatures map[fpr]sig` / `SignerKeys` / `Endorsements` (`tui/record/sealed.go`).
- Each seal signature is over `protocol.SealSigningBytes(room, head)` (v1,
  `record_signing.go:106`) or `SealSigningBytesV2(room, meaning, name, signedAt, head)`
  (v2, `:129`) — over the **head**, never over the signature *set*.
- Therefore **adding a verified co-signature later touches only the signature maps.**
  `Entries` and `HeadHash` are unchanged; the chain stays intact; **both** the `{A}` and
  `{A,B}` versions `Verify()` VALID, and the second **strictly dominates** (superset of
  signatures).
- Co-signatures **cannot be forged**: `onSealAck` and `Verify()` both re-derive the
  preimage and require `ed25519.Verify` against the signer's identity key.
- **The only cost of amendment is byte-stability:** the amended `record.json` differs from
  the first-written file, so a hash/QR captured of the 1-sig version won't match the 2-sig
  version (both verify independently — they are just different bytes). This raises an
  "authoritative copy" question but presents **no cryptographic obstacle**.

**Consequence:** a late verified co-signature can always be *added* to a finalized record
without weakening or re-opening any cryptographic property. Amendment is essentially free.

---

## 3. The central design hole — no expected signer set

There is **no notion of an expected signer set for seals** anywhere. No `[action.seal]`
quorum exists. The only denominator is `len(c.order)` — dynamic, initiator-local, racy,
evaluated at finalize time, and **signed into nothing** (absent from the record entirely).
This is *why* immediate-finalize happens, *why* "wait for the co-signer specifically" never
occurs, and *why* `verify` cannot know a signature is missing. Any fix that wants the record
to *self-certify who was expected* must put that set into signed bytes — a **versioning
event** (see §5.B, §6).

## 4. The working reference pattern

The artifact flow (`tui/client/artifact.go`, `countArtifactApproval`) gets multi-party
attestation right: an explicit fixed quorum (`tp.prop.Quorum`), `reached = count >= needed`,
a **deterministic single writer** (`minFpr(approvers)`) so exactly one client persists
without forking, and **retained proofs re-attached at seal time**. Seals have neither an
explicit expected count nor a principled writer rule. We mirror the *deterministic single
writer* and *retained-proof* discipline; we do **not** import an explicit signed quorum
(that is the deferred versioning event).

---

## 5. Design analysis and recommendations

### Decision A — core fix shape: **HYBRID** (recommended)

| Property | WAIT | AMEND (pure) | **HYBRID (recommended)** |
|---|---|---|---|
| Race 1 (order==1 immediate) | Only if it can *prove* "not yet synced" — undecidable in the moment | Fixed (late ack amends) | **Fixed** (late ack amends) |
| Race 2 (post-timeout) | **Not fixed** — any bounded wait drops the tail; unbounded wait hangs solo | Fixed | **Fixed** |
| Solo sealer finalizes instantly | Risk of hanging; needs a timeout, which *reintroduces* the tail-drop | Instant | **Instant** |
| Byte-stability, common synced case | Good (one write) | Worse (may write at 1 sig, then rewrite) | **Good** (collection window still yields one write) |
| Implementation complexity | High (needs a trustworthy "synced" signal — the exact broken thing) | Moderate | **Moderate** (AMEND + keep existing window) |

**Why WAIT alone fails.** WAIT is in irreducible tension with the solo-sealer constraint.
To not hang a genuinely alone sealer, any wait must be *bounded* — but a bounded wait has a
tail in which a co-signer who acks after the bound is dropped (race 2 unchanged). An
*unbounded* wait hangs the solo case. And its correctness hinges on a defensible
"membership is synced" signal, which is precisely what is broken. WAIT can only *narrow*
the race window; it cannot close it.

**Why pure AMEND is suboptimal.** AMEND is correct (a late signature can never be lost),
but if it finalizes at the first opportunity (including `order == 1`) it rewrites
`record.json` in the *common synced case* too, producing avoidable churn and worsening the
authoritative-copy question.

**Why HYBRID.** HYBRID = **keep eager finalize** (so a solo seal never hangs) **+ keep the
existing collection window** (so a *synced* 2-party seal still collects all present
signatures before the first write — one byte-stable write, `TestSealRoundTrip` unchanged)
**+ amend on stragglers** (so no signature is ever lost under either race). Because the
collection window already exists in the code, HYBRID is barely more than pure AMEND, and it
buys byte-stability in the common case for free. The eager `order == 1` finalize is **not
removed** — it is made *safe* by the amend backstop. Amendment being cryptographically free
(§2) is what makes the backstop cheap. **Recommend HYBRID.**

**Mechanism (design-level; no code here).**

1. **Retain the finalized seal as an amendable snapshot.** On `finalizeSeal`, instead of
   niling the seal context, transition it into a retained `lastSeal` snapshot holding
   `{head, entries, sigs, keys, endorse, artifactProofs-ref}`. The *initial* finalize keeps
   its current "first caller wins" idempotency (early-completion vs. the 30 s timer).
2. **Accept late acks instead of dropping them.** Replace the `if !c.sealing { return }`
   guard in `onSealAck` with three branches:
   - *actively sealing, head matches* → current path (verify → add → `maybeFinalize`);
   - *not sealing, head matches `lastSeal.head`, signer not already recorded* → **amend**:
     ed25519-verify the preimage, add to the retained maps, re-assemble the record, re-emit
     `EvSealComplete` (which re-persists via the existing writer);
   - *stale / divergent head* → **emit a diagnostic** (never a silent drop; see Decision C).
3. **Preserve locking discipline.** Verify + map-mutate under `c.mu`, snapshot, then
   assemble and emit outside the lock — mirroring the existing `finalizeSeal` pattern.
4. **Idempotency.** Amend is a no-op when the signer is already present (no rewrite, no
   double-count). Duplicate acks are harmless.
5. **Retention window (bounded).** The `lastSeal` snapshot stays amendable until it is
   *superseded* by a new seal round, or the room key rotates / `/vanish` / scuttle, or the
   session ends. A late ack for a stale epoch fails decryption naturally, so the window is
   self-bounding; memory cost is one seal's worth.
6. **Deterministic writer discipline.** The initiator remains the sole writer of its own
   durable copy (mirroring the artifact single-writer rule); amendment re-writes *in place*
   on the initiator. (Whether to *distribute* the finalized record to peers is Decision C /
   an open question, not required for correctness.)

### Decision B — what defines the "expected signer set"

**Recommendation: do not introduce a signed expected-signer-set in this fix; keep
`len(c.order)` only as an *advisory completion hint*, and make correctness independent of
it via HYBRID.**

Reasoning:

- With HYBRID, the denominator's job shrinks to "when should the initiator do the *first*
  (byte-stable) write?" — an **optimization**, not a correctness gate. Amend backstops any
  under-count, so a racy denominator can no longer *lose* a signature. We therefore do
  **not** need a bulletproof expected set for correctness.
- Baking an expected set into signed bytes is the only way for the record to
  **self-certify who was expected** — but the expected set is *itself* racy and
  ill-defined at signing time (that is the whole bug). Signing "expected = {A,B}" would make
  a racy, initiator-local snapshot *permanent and authoritative* — arguably worse than not
  claiming it. It also mandates a new `SealSigningBytesV3` + `PROTOCOL.md` — a **versioning
  event**.
- An *unsigned* advisory expected-count could let `verify` warn "expected 2, found 1" for
  the *accidental* case without a version bump — but it is strippable (no anti-tamper
  value), and once HYBRID prevents the loss the record won't *be* under-signed in the first
  place, so it adds noise for little gain. Recommend **skipping** it.

**Explicit versioning statement:** the recommended B **does not** touch any preimage or wire
struct → **no versioning event.** The self-certifying expected set (`SealSigningBytesV3`) is
the "real" answer to "verify should prove multi-party expectation offline," and it **is** a
versioning event — flagged loudly and **deferred** to its own milestone (§6), because
(i) it needs its own design (config quorum vs. named set vs. attendance snapshot),
(ii) HYBRID already prevents the *loss* that is the actual bug, and (iii) smuggling a format
version into a data-loss fix is exactly what the versioning gate exists to prevent.

### Decision C — close the silent-failure gaps

**Recommendation: close the gaps that are cheap and client-local now; defer the ones that
require new protocol surface, clearly flagged.**

- **Sealer-side silence — FIX NOW (no wire change).** Replace the silent post-finalize
  `return` in `onSealAck` with the amend path (§5.A) and, for an ack that genuinely cannot
  be applied (stale/divergent head, or already-present signer), emit a diagnostic event.
  Emit an amend signal (e.g. `EvSealComplete` with an `Amended` marker / updated signer
  count) so the record is re-persisted and the UI can show *"record updated — now N
  signatures."* This directly removes the silence that hid the bug.
- **Co-signer-side over-claim — CHEAP FIX NOW (no wire change).** Reword the co-signer's
  local message so it does **not** over-claim: it states the co-signature was *sent* (and
  will be recorded when the round closes), rather than asserting it was recorded. Pure
  client string change.
- **Co-signer "RECORDED" confirmation — DEFER / SEPARABLE (additive wire, not a signed-bytes
  version bump).** A true "your signature was recorded (N/M)" signal requires the sealer to
  broadcast a completion/receipt the co-signers observe — a **new Op or reuse of an existing
  envelope + `PROTOCOL.md` update**. This is an *additive protocol surface*, **not** a
  signed-bytes versioning event, and it would also let all members converge on the
  authoritative finalized record (softening the single-writer "authoritative copy" concern).
  Recommend it as a **near-term follow-up**, kept out of the core fix for anti-bloat; the
  core fix stands without it.
- **`verify` reports "fewer than expected" — DEFER (depends on B's versioning event).**
  `verify` can only know a signature is *missing* if the expected set is durably (and, to
  resist tampering, *signed*) in the record — the `SealSigningBytesV3` gate. Since HYBRID
  prevents the loss at the source, verify-side detection is *defense-in-depth*, not the
  primary fix. Deferred with §6.

---

## 6. Versioning gate — explicit determination

**The recommended fix (HYBRID amend + sealer-side diagnostics + honest co-signer wording)
does NOT trigger the versioning gate.**

- No change to `SealSigningBytes` / `SealSigningBytesV2` preimages.
- No change to `SealRequestBody` / `SealAckBody` wire structs.
- No new `Op` in the core fix.
- Therefore **no signed-bytes change, no new preimage version, no `PROTOCOL.md` change** for
  the core fix.

**Deferred enhancements that DO trip gates (flagged loudly, out of scope):**

1. **Signed expected-signer-set** → new `SealSigningBytesV3` + `PROTOCOL.md`. A *true*
   versioning event. This is the only path by which `verify` can offline-detect an
   under-signed record.
2. **Completion/receipt broadcast** (co-signer "recorded" confirmation + record convergence)
   → additive wire `Op` + `PROTOCOL.md`. A protocol-surface addition, **not** a signed-bytes
   version bump — but still a wire change requiring `PROTOCOL.md`, so it ships as its own
   scoped change, not inside the data-loss fix.

If, during build, any element is found to require changing signed bytes, **stop and
re-scope** — that is a versioning event and belongs in a separate, explicitly-versioned
change.

---

## 7. Invariant register

| # | Invariant | Enforced by |
|---|---|---|
| INV-1 | A genuinely solo sealer finalizes **instantly** with exactly its own signature and never hangs. | Eager finalize retained; amend never blocks the first write. |
| INV-2 | **No verified co-signature for the sealed head is ever lost** — a late ack amends the durable record. | `onSealAck` amend branch + retained `lastSeal`. |
| INV-3 | Initial `finalizeSeal` remains idempotent — first of {early-completion, timer} wins; the other is a no-op. | Unchanged finalize guard. |
| INV-4 | Amendment is **monotonic & additive** — only signatures are added; `Entries`/`HeadHash` never change; every version `Verify()`s VALID; a later version is a superset. | Detached-signature model (§2); amend touches only signature maps. |
| INV-5 | A co-signature is recorded **only after ed25519 verification** over the correct (v1/v2) preimage; forged/unverified sigs never enter the record (amend re-verifies). | `onSealAck` verify + `Sealer` re-check. |
| INV-6 | Duplicate acks from an already-recorded signer are **no-ops** (no rewrite, no double-count). | "signer not already present" amend guard. |
| INV-7 | **Artifact-proof attachment is preserved** across both initial finalize and amend — matching artifact entries keep their approvals. | Re-run the `record.go:328-339` attachment on amend from retained entries/proofs. |
| INV-8 | Blind-relay import boundary holds — fix is client-side; `TestServerBinaryDoesNotLinkClientCrypto` stays green. | No server-tree/crypto import added. |
| INV-9 | **No signed bytes / no wire struct / no new Op** → `PROTOCOL.md` unchanged; no format version bump. | §6. |
| INV-10 | An ack that cannot be applied (stale/divergent head) produces an **emitted diagnostic**, never a silent drop. | `onSealAck` diagnostic branch. |
| INV-11 | The co-signer's local UX does **not over-claim** — it states the signature was *sent*, upgrading to "recorded" only if/when the deferred completion broadcast ships. | Reworded co-signer message. |

---

## 8. Test plan

Reproduce **both races**, prove the fix closes them, and pin the invariants. Helpers
(`connectCore`, `twoMembers`, `waitKeyReady`, `waitMatch`) already exist in the seal/scuttle
test suites.

1. **`TestSealImmediateFinalizeRaceAmends`** (race 1 + headline regression, INV-2): the
   initiator seals **without** waiting for `EvMemberJoined` (forces `order == 1`); assert an
   immediate 1-signature finalize occurred; the co-signer then co-signs late; assert the
   initiator's durable record (from the amended `EvSealComplete`) now carries **2**
   signatures, both verify, `Verify()` VALID. This is the test the current suite *lacks* —
   the companion to `TestSealRoundTrip` that does **not** wait.
2. **`TestSealPostTimeoutLateAckAmends`** (race 2, INV-2): with a **test-injectable**
   `sealTimeout` (see infra note), `order == 2` but the co-signer acks after the timer
   finalized; assert the amend lands the second signature. *(Shares the amend code path with
   test 1; both races converge post-finalize.)*
3. **`TestSoloSealerFinalizesInstantly`** (INV-1): single member; `/seal` finalizes
   immediately with 1 signature, VALID, never hangs (bounded wait in the test); no amend
   occurs.
4. **`TestSealRoundTrip`** (existing — must stay green, INV-3): synced 2-party still
   collects both signatures before the first write; **one** write; VALID; no amend.
5. **`TestLateCosignatureIsDurable`** (HYBRID core, INV-2/INV-4): after finalize, deliver a
   valid late ack; the re-emitted/written record contains it; VALID with 2 signatures; the
   `{A}` and `{A,B}` records both verify.
6. **`TestAmendIsIdempotentOnDuplicateAck`** (INV-6): deliver the same co-signer's ack twice
   post-finalize; exactly one signature recorded; at most one rewrite.
7. **`TestAmendPreservesArtifactProofs`** (INV-7): a seal whose entries include an artifact
   entry with retained proofs; after amend, the record still carries the artifact approvals
   and `Verify()` VALID.
8. **`TestUnapplicableAckEmitsDiagnostic`** (INV-10): a stale/divergent-head ack after
   finalize produces an emitted event/diagnostic (asserted), not a silent drop.
9. **`TestAmendRejectsForgedCosignature`** (INV-5): an ack whose signature does not verify is
   rejected and does **not** amend the record.
10. **Boundary guard** (INV-8): `TestServerBinaryDoesNotLinkClientCrypto` stays green — no
    new import.

**Test infra note (non-wire, flagged):** deterministically exercising the post-timeout path
(test 2) wants `sealTimeout` to be overridable. It is currently a package `const`
(`client.go:157`); making it a `var` or a client field is a **trivial, client-only, non-wire
change** with no signed-bytes impact. If preferred, tests can instead rely on the fact that
the `order == 1` immediate-finalize path (test 1) reaches the **same** post-finalize amend
code as the timeout path, and treat test 2 as optional coverage.

---

## 9. What this is NOT doing (anti-bloat)

- **NOT** introducing a signed expected-signer-set / seal quorum / `SealSigningBytesV3`.
  That is the deferred versioning-event milestone (§6).
- **NOT** adding server-side or relay-side enforcement — seals are client-side; the blind
  relay is untouched.
- **NOT** changing the hash chain, `Entries`, `HeadHash`, or entry signing — only the
  **detached signature set** is amended.
- **NOT** changing `SealRequestBody` / `SealAckBody` wire formats or adding a new `Op` for
  the core fix (the completion/receipt broadcast is a separable, flagged follow-up).
- **NOT** making `verify` report "fewer than expected" — that depends on the deferred signed
  expected-set.
- **NOT** removing eager finalize or making the solo sealer wait — solo stays instant.
- **NOT** a general membership-synchronization fix — we do **not** try to make `c.order`
  authoritative or consistent; we make correctness *independent* of it.
- **NOT** unbounded retention — the amendable window is bounded by supersession / epoch
  rotation / `/vanish` / scuttle / session end.

---

## 10. Open questions

1. **Retention window precision.** Exact boundary at which `lastSeal` stops being amendable —
   proposal: superseded by a new seal, or epoch rotation / `/vanish` / scuttle, or session
   end. Confirm acceptable.
2. **Record convergence.** Should the amended record be broadcast so all members hold the
   authoritative copy (the completion-broadcast, §5.C Tier 3)? Softens the single-writer
   "authoritative copy" concern but is an additive wire `Op`. In or out of this fix?
   *(Recommendation: out — separate scoped change.)*
3. **Byte-stability policy.** Is in-place rewrite of `record.json` on amend acceptable
   (recommended, with a clear "record updated — now N signatures" message), or should an
   amend write a versioned filename to preserve the earlier bytes? *(Recommendation:
   in-place + message.)*
4. **`sealTimeout` injectability.** Promote the `const` to a test-overridable `var`/field for
   deterministic post-timeout testing? *(Recommendation: yes — trivial, non-wire.)*
5. **Co-signer wording.** Confirm the reworded local message ("co-signature sent — the sealer
   records it when the round closes") pending the optional full "recorded" confirmation.
6. **Advisory expected-count.** Skip it entirely (recommended — HYBRID prevents the loss and
   an unsigned count is strippable noise) or add it as a stepping stone toward the signed
   V3? Confirm skip.
