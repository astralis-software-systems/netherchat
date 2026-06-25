# Role-Typed N-of-M Quorum — Implementation Plan

> **Status:** Plan only. No code written. Three build passes (A, B, C) are
> specified here; **only Pass A is approved to build next**. Passes B and C are
> designed but explicitly *not-yet-built*.
>
> **Goal:** Pharma segregation-of-duties (SoD) approval — *"one verified approver
> from each required function (e.g. Technical + QA + System-Owner)"* — built on the
> offline artifact-proof mechanism and enforced by the downstream consumer
> (CipherSigil), with the Netherchat library remaining policy-free.
>
> **Repos:** Netherchat (`C:\Users\saleh\netherchat`, public, AGPL, `main`) and
> CipherSigil (`C:\Users\saleh\ciphersigil`, private, `master`), which embeds
> Netherchat via `replace github.com/salehkreiner/netherchat => ../netherchat`.

---

## 1. Scope & mechanism map

There are three approval mechanisms in the codebase. This work targets exactly one.

| Mechanism | Where | Role in this work |
| --- | --- | --- |
| **M1 — Live relay artifact flow** | `tui/client/artifact.go`, protocol `Op*Artifact*`, `protocol/artifact.go` (`ArtifactProposalBody.Quorum`) | **OUT OF SCOPE.** Has a runtime count-quorum (`count >= needed`, `client/artifact.go:365`). Do **not** modify. Only the byte already produced by this flow (the v1 approval proof) is shared with M2. |
| **M2 — Offline sealed-record artifact proofs** | `tui/record` (`SealedRecord.ArtifactApprovals` → `VerifyResult.ArtifactApprovers`), preimage `protocol.ArtifactApprovalSigningBytes` | **TARGET.** Pass A hardens its v1 substrate; Pass B adds a role-carrying v2 proof. |
| **M3 — CipherSigil deliverable seal-endorsement workflow** | `internal/workflow/workflow.go` (`Decide`/`Seal`/`validateSealPolicy`), seal endorsements (`SealSigningBytesV2`) | **OUT OF SCOPE.** This is CipherSigil's *own* two-person deliverable machinery (KindTyped entry + seal endorsements). It is a different substrate and produces an *empty* `ArtifactApprovers`. Do not modify; note only incidental interaction. |

**Why M2 and not M3:** the requirement is to verify approvals of *agent-produced
artifacts* by *named humans of specified functions*, offline and from the record
alone. That is precisely what M2's record-level `ArtifactApprovals` proofs are
(self-authenticating, not covered by any entry/seal signature, surfaced as
`VerifyResult.ArtifactApprovers`). M3's endorsements bind a *meaning* but live on
the seal head and are tied to CipherSigil's deliverable lifecycle, not to a foreign
artifact.

**The core gap:** M2's approval preimage
`protocol.ArtifactApprovalSigningBytes(proposalID, artifactHash, approverFpr, nonce)`
(tag `netherchat/artifact-approval/v1`, `protocol/artifact_signing.go:22-30`) binds
**no role and no meaning**. So *"I signed this as the QA reviewer"* is not
cryptographically expressible today. Role-typed quorum cannot be honest without
closing that gap — hence Pass B adds a role to the signed bytes.

### Explicitly NOT in scope (anywhere in this work)
- No change to M1 (live relay flow) or M3 (deliverable workflow).
- No change to the SSH-wire fingerprint dialect, the `internal/` import boundary, or
  the blind-relay guard.
- No new server-side code; the server cannot and must not link any of this.
- No general "policy engine" in the library. The library stays policy-free: it
  *surfaces* verified role-attributed approvers; it enforces **no** threshold.

---

## 2. Invariant register (checklist for every pass)

Each pass must leave **all** of these green. Cite the enforcing test in the pass's
verification step.

| # | Invariant | Enforcing test / mechanism |
| --- | --- | --- |
| I1 | Old (pre-v2) records still verify VALID, unchanged | `tui/record/record_v2_test.go` → `TestVerifyOldFormatRecordStillValid` |
| I2 | Old artifact records (six original `ArtifactMeta` fields) round-trip **byte-identically** and surface an empty approver set | `tui/record/artifact_proof_test.go` → `TestOldArtifactRecordByteIdenticalNotTwoPerson` |
| I3 | New fields are **record-level + `omitempty`** and **NEVER** enter an entry's or seal's canonical signing bytes | `Entry.canonical()`/`Entry.extended()` (`record.go:117-131`); `ArtifactApprovals`/`Endorsements` are `omitempty` and excluded from preimages (`sealed.go:99-100,314-320`) |
| I4 | v1→v2 schema extension follows the **content-gated, new-domain-tag** precedent | `RecordSigningBytesV2` + `TestRecordV2DiffersFromV1` (`protocol/v2_signing_test.go:67`) |
| I5 | Strict JSON: unknown top-level field or trailing data → **whole record rejected** (forward-incompat) | `Parse` (`sealed.go:166-177`); `TestRoundTripDisallowUnknownFields` (`sealed_test.go:133`) |
| I6 | Façade re-exports the **entire** public surface; a new exported symbol unre-exported = build failure | `sealedrecord/surface_test.go` → `TestFacadeReexportsFullPublicSurface` |
| I7 | SSH-wire fingerprint dialect stays distinct from CipherBond's raw-key dialect; external fingerprinting routes through `record.Fingerprint`/`sealedrecord.Fingerprint` | `tui/internal/crypto/byokey_test.go` → `TestSSHKeyFileFingerprintMatchesSSH`; `tui/record/fingerprint.go` |
| I8 | Domain-tag separation: every new preimage has its own tag; a sig from one context never verifies in another | new `TestArtifactApprovalV2DiffersFromV1` (Pass B) + the existing per-tag vectors |
| I9 | `VerifyResult.Valid` defaults false; set true only after **all** checks pass (fail-closed for bad/forged/orphan/nonce-less proofs) | `Verify` (`sealed.go:232-334`); `artifact_proof_test.go` forgery/fail-closed tests |
| I10 | Author + proposer exclusion and per-fingerprint distinctness hold for the surfaced set | `TestArtifactProofAuthorAndProposerExcluded`, `TestArtifactProofDuplicateCountedOnce` (`artifact_proof_test.go`) |
| I11 | CipherSigil's `replace`-linked build (`cd ciphersigil && go build ./...`) is green at **every** commit | manual gate in order-of-operations (§8) |

CI gates that must also stay green throughout: `gofmt -l .` (empty), `go vet ./...`,
`go test -race ./...`, and `just check-boundary`
(`TestServerBinaryDoesNotLinkClientCrypto`).

---

## 3. Three-pass decomposition

```
Pass A  (Netherchat)   FOUNDATION — pin & harden the v1 artifact-approval substrate.
                        Test-only. Zero behavior change. Build this next.
                        → tag v1.9.0 afterward (closes the untagged-API gap).

Pass B  (Netherchat)   v2 ROLE STRUCTURE — add `netherchat/artifact-approval/v2`
                        (v1 fields + role), an omitempty `Role` on ApprovalProof,
                        per-proof verifier dispatch, role surfacing in VerifyResult,
                        façade re-exports, report rendering. Fully v1-backward-compat.
                        → tag v1.10.0 (additive; forward-incompat warning in notes).

Pass C  (CipherSigil)  CONSUMER POLICY — role-aware roster, role-typed quorum
                        enforcement from deployment config, version/tag housekeeping
                        (go.mod require bumps). Selects role-mode vs count-mode by config.
```

**Boundaries:**
- Pass A touches **only** Netherchat `protocol/` test code. No production `.go` edits.
- Pass B touches **only** Netherchat (`protocol/`, `tui/record/`, `tui/report/`,
  `sealedrecord/`). It is **purely additive** — no existing exported signature
  changes, no existing record/proof bytes change — so CipherSigil keeps compiling
  unmodified against post-Pass-B Netherchat.
- Pass C touches **only** CipherSigil, consuming the already-landed additive API.

---

## 4. Design recommendations (open questions 1–6)

### Q1 — Role model: extend `Meaning`, or a distinct `role` field?

**Recommendation: a distinct, opaque `role` field. Do NOT overload `Meaning`. Do
NOT also add name/signedAt to the v2 artifact preimage.**

Reasoning / tradeoffs:

- **Role and approval-act are orthogonal.** `Meaning` answers *"what act?"*
  (authored/reviewed/approved/rejected). Role answers *"acting as which function?"*
  (QA/Technical/System-Owner). Folding them into one string
  (`meaning="qa-approved"`) creates a combinatorial vocabulary
  (qa-approved, qa-rejected, technical-approved, …) and is the dishonest reading for
  an auditor. *"The QA reviewer approved this artifact"* (role + act as separate
  signed facts) reads cleanly; *"an approval with meaning=qa-approved"* does not.
- **M2 artifact proofs have no rejection concept.** In the offline proof world there
  are only *approvals* — M1's `RejectArtifact` writes **no** record entry/proof
  (`client/artifact.go:219-247`). So a `meaning` on an artifact proof would be a
  near-constant `"approved"`: low value, real surface cost. The genuinely missing,
  load-bearing dimension is **role**.
- **Name is already handled better elsewhere.** CipherSigil deliberately resolves
  printed names from the operator-controlled roster and distrusts self-asserted
  names (`workflow.go:531-536` derives identity from `PubKey`, not the persisted
  name). Binding a self-asserted `name` into the artifact preimage would invite the
  exact spoofing that code rejects. Timestamps already exist at the record level
  (`ArtifactMeta.ApprovedAt`/`ProposedAt`). So adding name/signedAt to the preimage
  (as action-approval-v2 does) buys little here and adds bytes.
- **Cryptographic cleanliness.** A single new opaque signed string mirrors how the
  library already treats `Meaning` and `Schema` (opaque, signed, consumer-defined
  semantics). The library attaches **no** meaning to the role value.

**What we are NOT adding (Q1):** no `meaning`, no `name`, no `signedAt` in the v2
artifact-approval preimage. Just `role`. (If a future need for reject-with-role or
reviewed-vs-approved-role distinction arises, that is a *later* v3, not this work.)

### Q2 — Where do N and the required-role set live?

**Recommendation: split the two concerns by their trust requirement.**

- **The role each approver SIGNS WITH → in the signed bytes (the record).** This is
  non-negotiable: role must be *cryptographically attributable* to the approver, or
  "signed as QA" is just a claim. It goes into the v2 preimage (Q3) and onto the
  proof as an `omitempty` record-level field.
- **The policy "which roles are required for this action class, and the threshold"
  → consumer/deployment config (CipherSigil).** Not in the record.

Reasoning / tradeoffs:

- Keeping the *required-role policy* out of the record preserves the
  **policy-free-library** principle (the library never decides what is "enough").
- Encoding required-roles in the record would trip **I5 (strict JSON
  forward-incompat)**: any new top-level record field makes *every* pre-upgrade
  verifier reject the whole file. A deployment SOP ("we require QA+Technical for
  risk-class X") can also legitimately differ by site and evolve over time *without
  re-sealing already-issued records* — it does not belong frozen in the artifact.
- The signed *per-approver role* (in the record) is exactly what lets the consumer's
  *config policy* be checked against ground truth at verify time.

**What we are NOT adding (Q2):** no required-role list, no quorum threshold, and no
policy object inside the sealed record or `ArtifactMeta`.

### Q3 — `netherchat/artifact-approval/v2` preimage layout

Follow the **action-approval v1→v2 precedent verbatim** (`protocol/action_signing.go`:
v2 = v1 fields, then new field(s), under a new tag). Proposed:

```
Layout (artifact-approval v2):

    field("netherchat/artifact-approval/v2")
      || field(proposal_id) || field(artifact_hash) || field(approver_fpr) || field(nonce)
      || field(role)

where field(b) = uint64-big-endian(len(b)) || b.   // injective, same as v1
```

New function (Pass B): `protocol.ArtifactApprovalSigningBytesV2(proposalID,
artifactHash, approverFpr, nonce, role string) []byte`. The v1 function is left
**untouched**.

**Coexistence in `ArtifactApprovals[pid]`:** the bag holds a mix of v1 and v2
proofs. `ApprovalProof` gains one field:

```go
type ApprovalProof struct {
    ApproverFpr string `json:"approver_fpr"`
    ApproverKey string `json:"approver_key"`
    Sig         string `json:"sig"`
    Role        string `json:"role,omitempty"` // NEW — absent ⇒ v1 proof
}
```

**Verifier dispatch is per-proof, content-gated** (the `Entry.extended()` precedent,
I4): in `verifyArtifactApprovals` (`sealed.go:344-407`), for each proof —
- `Role == ""` → reconstruct the **v1** preimage (`ArtifactApprovalSigningBytes`),
  verify byte-identically as today;
- `Role != ""` → reconstruct the **v2** preimage (`ArtifactApprovalSigningBytesV2`),
  verify.

**Backward-compat guarantees (cite I1/I2/I4/I8):**
- A v1 proof has no `Role` → `omitempty` omits the key → JSON is byte-identical →
  v1 preimage → identical verification. (I2 holds; the new field never appears.)
- Old records carry no `ArtifactApprovals` at all → the whole block is skipped
  (`sealed.go:321`). (I1/I2.)
- The new domain tag means a v2 signature can never be confused with a v1 one, and
  flipping role membership flips the tag (I8). A new
  `TestArtifactApprovalV2DiffersFromV1` pins this.
- Role is an **opaque** signed string; the library validates nothing about its value
  (consumer owns the vocabulary), exactly like `Meaning`/`Schema`.

The author/proposer exclusion and per-fingerprint distinctness (I10) are unchanged
and applied to the combined v1+v2 set before surfacing.

**What we are NOT adding (Q3):** no change to the v1 function or tag; no extra fields
beyond `role`; no binding of proposer/quorum into the proof (exclusion stays a
surface-layer string match).

### Q4 — Surfacing roles in `VerifyResult`

**Recommendation: keep `ArtifactApprovers` exactly as-is; add a parallel,
`omitempty` role map.** Replacing the field's shape would break the existing
accessor and CipherSigil's current call site (`VerifiedArtifactApprovers(res, pid)
[]string`), so additive is mandatory (I6 also requires re-exporting whatever we add).

```go
type VerifyResult struct {
    // ... unchanged ...
    ArtifactApprovers map[string][]string `json:"artifact_approvers,omitempty"` // UNCHANGED: distinct verified fprs (role or not)

    // NEW, additive, omitempty: per proposal, the role-attributed (v2) approvers.
    ArtifactApproverRoles map[string][]VerifiedApprover `json:"artifact_approver_roles,omitempty"`
}

type VerifiedApprover struct {
    Fingerprint string `json:"fingerprint"`
    Role        string `json:"role"`
}
```

- `ArtifactApprovers` remains the role-agnostic distinct set (superset) — existing
  count-based callers and `VerifiedArtifactApprovers` keep working unchanged.
- `ArtifactApproverRoles` contains only **v2** (role-bearing) approvers, after the
  same author/proposer exclusion + distinctness, sorted deterministically (by
  fingerprint, then role) for stable JSON.
- New nil-safe accessor `VerifiedArtifactApproverRoles(res *VerifyResult, proposalID
  string) []VerifiedApprover`, mirroring the existing accessor.
- **I6:** `VerifiedApprover` (type), `VerifiedArtifactApproverRoles` (func), and
  `ArtifactApproverRoles` (field, surfaced automatically via the `VerifyResult`
  alias) must be re-exported in `sealedrecord/sealedrecord.go`, or the surface guard
  fails the build. The plan's Pass B file list includes this.

**`report.go` rendering:** `approverDisplay` (`tui/report/report.go:82-95`) currently
renders the plain fpr set. Extend it to prefer `ArtifactApproverRoles` when present —
e.g. *"QA reviewer — SHA256:… ; Technical reviewer — SHA256:…"* — falling back to the
existing roleless display when a proposal has only v1 proofs. Purely presentational;
no policy.

**What we are NOT adding (Q4):** no change to the existing field's type/JSON; no
role→fpr nested maps (awkward to keep JSON-stable); no policy verdict in the result.

### Q5 — Consumer enforcement design (Pass C, CipherSigil)

Today: `ArtifactRecordIsTwoPerson(b []byte, roster Roster, n int) error`
(`internal/record/artifact.go:110-145`) counts `verified ∩ roster ≥ n` per proposal,
all-or-nothing. `Roster` is `map[string]string` (fpr→name).

**Recommendation: AUGMENT, don't replace.** Keep `ArtifactRecordIsTwoPerson`
(count-mode, fully tested, unchanged) and add a role-typed sibling. Deployment config
selects the mode per action-class.

1. **Roster gains role information.** This is required for honest SoD: the signed
   role proves *"X signed as QA"*, but **not** *"X is authorized to act as QA."*
   Without an authorization binding, any rostered member could self-declare any role
   — re-opening forgery at the role layer (the GAP-5 problem, one level up). So:
   ```go
   type Roster map[string]RosterMember
   type RosterMember struct {
       Name  string
       Roles []string // functions this fingerprint is authorized for, e.g. {"qa","technical"}
   }
   ```
   `Roster.Name(fpr)` is preserved (returns `member.Name, ok`) so count-mode and all
   existing call sites keep compiling with a one-line accessor change; add
   `Roster.HasRole(fpr, role) bool`.

2. **New enforcement entry point** (role-mode), e.g.:
   ```go
   func ArtifactRecordMeetsRoleQuorum(b []byte, roster Roster, requiredRoles []string) error
   ```
   Per proposal, for **each** required role `R`: require **≥1** verified approver
   whose *signed* role == `R` (from `VerifiedArtifactApproverRoles`) **and** whose
   fpr is authorized for `R` in the roster (`roster.HasRole(fpr, R)`) — i.e. the
   role-layer analog of `verified ∩ roster`, now `verified-as-R ∩ roster-authorizes-R`.
   All-or-nothing across proposals and across required roles; fail-closed; name the
   first unmet (proposal, role). Reuse the `ErrNoArtifactApprovals` sentinel for
   "valid record, no artifact proposals."

3. **Distinct-person across roles (SoD core).** Pharma SoD requires *different
   people* for segregated duties. The library faithfully surfaces every
   `(fpr, role)` pair (including the same fpr under two roles if it signed twice), so
   the consumer enforces "each required role filled by a **distinct** fpr." **This is
   a policy decision — flagged in §9 for confirmation.** Recommended default:
   distinct persons required.

4. **How `n` / `MinArtifactApprovers` relate.** Count-mode (`n`) and role-mode
   (`requiredRoles`) are distinct policies, chosen per action-class in config.
   Role-mode subsumes the two-person intent: "≥1 of each of ≥2 distinct roles" ⇒ ≥2
   distinct authorized people. `MinArtifactApprovers = 1` stays the count-mode
   default; it is not used in role-mode.

5. **Where required-role config lives.** CipherSigil deployment config
   (`internal/config`), as a per-action-class policy (mode + either `n` or
   `requiredRoles`). Per Q2, the policy is consumer-side, never in the record.

6. **Files that change in Pass C** (CipherSigil only):
   - `internal/record/artifact.go` — add `ArtifactRecordMeetsRoleQuorum`,
     `recognizedApproversByRole` helper; keep `ArtifactRecordIsTwoPerson`.
   - `internal/record/seal.go` — change `Roster` to `map[string]RosterMember`, add
     `RosterMember`, update `Roster.Name`, add `Roster.HasRole`.
   - `internal/config/…` — load the role-aware roster and per-action-class quorum
     policy; the roster file format gains roles.
   - Call sites that construct/consume `Roster` (e.g. `internal/workflow`,
     `internal/core`, tests) — update to the new type. **Note:** M3's
     `validateSealPolicy` uses `roster.Name` only; it keeps working via the preserved
     accessor and is otherwise untouched (out of scope).
   - `internal/record/artifact_test.go`, `internal/config/roster_test.go` — extend
     for role-mode; keep count-mode tests intact.
   - `go.mod` — require bump (Q6).

**What we are NOT adding (Q5):** no role logic in the Netherchat library; no rewrite
of `ArtifactRecordIsTwoPerson`; no change to M3's workflow; no role policy baked into
records.

### Q6 — Tag / version housekeeping

Reality (verified): latest tag `v1.8.0` → commit `79a7fce`, which **predates the
entire artifact-approval API**. The merged-but-untagged artifact work (`877bc6b` +
merge `69ebbce`) is on `origin/main` with **no tag**. CipherSigil's `go.mod` requires
`v1.8.0` (which lacks `VerifiedArtifactApprovers`, `VerifyResult.ArtifactApprovers`,
`ArtifactMeta.ProposalID`) and only compiles via the local `replace`.

**Recommendation (sequence):**

1. **After Pass A lands → tag Netherchat `v1.9.0`.** Pass A's frozen byte-vector is
   part of hardening the *v1* substrate, so it belongs in the first tag that
   publishes the artifact-approval API. This closes the "no tag matches the consumed
   API" gap. `v1.9.0` is a minor bump (additive API already on main).
2. **Housekeeping: bump CipherSigil `go.mod` `require` `v1.8.0 → v1.9.0`** so the
   pinned version actually *contains* the API CipherSigil already uses. Keep the
   `replace => ../netherchat` for local development. (Can be done with Pass A's tag or
   at the start of Pass C; recommended with the `v1.9.0` tag for honesty.)
3. **After Pass B lands → tag Netherchat `v1.10.0`.** Additive (new optional field,
   new tag, new functions); existing records and v1 proofs verify identically, so it
   is a **minor** bump — consistent with how the v2 *entry/seal* schema shipped inside
   the v1.x line (v1.8.0 already contains record-v2).
4. **Pass C consumes the role API → bump CipherSigil `require` `v1.9.0 → v1.10.0`.**

**Release notes for `v1.10.0` MUST warn (I5 forward-incompat):**
> Records containing role-typed (`artifact-approval/v2`) approvals carry a new
> `role` field on each proof. Because verification uses strict JSON
> (`DisallowUnknownFields`), such records **fail to parse on verifiers older than
> v1.10.0** (the whole file is rejected). **Upgrade all verifiers to ≥ v1.10.0
> before producing any v2-artifact record.** Records *without* role-typed approvals
> are unaffected and remain byte-compatible.

**What we are NOT doing (Q6):** no major-version bump (no breaking change to existing
record verification); no removal of the `replace` directive during development; no
retroactive re-tag of `v1.8.0`.

---

## 5. Pass A build spec (BUILD THIS NEXT)

**Intent:** pin the v1 artifact-approval preimage with a frozen byte-vector (the only
preimage currently lacking one) and a binding test, mirroring
`protocol/action_signing_test.go`. **Pure no-behavior-change: test-only.**

### 5.1 What Pass A does and does NOT do
- **Adds** one new test file. **Adds no production code. Changes no production code.**
  It does **not** touch `protocol/artifact_signing.go`, any `tui/` file, the façade,
  `go.mod`, or any tag.
- It pins the *existing* `ArtifactApprovalSigningBytes` bytes exactly as they are
  today, so it is impossible for it to change behavior. (If the constant disagreed
  with the current output, the test would fail and the constant — not the function —
  would be corrected.)

### 5.2 File touched
- **NEW:** `C:\Users\saleh\netherchat\protocol\artifact_signing_test.go`
  (confirmed absent today).

### 5.3 Test content (spec)

Mirror `action_signing_test.go` exactly: a frozen-hex vector + a per-field binding
test. **Belt-and-suspenders:** also include an *independent re-derivation*
cross-check in the `refField`/`cat` style of `v2_signing_test.go`, so the frozen
constant is validated by construction and does not depend on hand arithmetic.

1. **`TestArtifactApprovalSigningBytesVector`** — frozen hex for fixed inputs.
   Use the same field values already verified in `action_signing_test.go` so three of
   the four field fragments are reused from a known-good source; only the domain-tag
   fragment is new.

   Inputs: `ArtifactApprovalSigningBytes("a3f9", "deadbeef", "SHA256:abc", "nonce0")`.

   Expected layout (field-by-field; `field(b)=u64be(len)||b`):
   - tag `"netherchat/artifact-approval/v1"` (len **31 = 0x1f**):
     `000000000000001f` +
     `6e6574686572636861742f61727469666163742d617070726f76616c2f7631`
   - `"a3f9"` (4): `0000000000000004` + `61336639`
   - `"deadbeef"` (8): `0000000000000008` + `6465616462656566`
   - `"SHA256:abc"` (10): `000000000000000a` + `5348413235363a616263`
   - `"nonce0"` (6): `0000000000000006` + `6e6f6e636530`

   > **Builder note:** the four non-tag fragments are copied verbatim from
   > `action_signing_test.go` (known-good). The tag fragment was hand-derived; the
   > re-derivation cross-check below is authoritative. **Run the test once on first
   > write; if the frozen constant disagrees with the actual output, the function is
   > unchanged and correct — replace the constant with the actual bytes (a typo in
   > the hand-derived tag, not a code bug).**

2. **`TestArtifactApprovalSigningBytesVectorRederived`** — independent re-derivation
   using `refField`-style helpers (an independent reimplementation of `writeField`),
   asserting it equals both the frozen constant and the production output. This
   catches a field **reorder** in the production function (the exact fragility this
   pass exists to close) without depending on the hand-typed tag hex.

3. **`TestArtifactApprovalSigningBytesBinding`** — flip each of `proposal_id`,
   `artifact_hash`, `approver_fpr`, `nonce` and assert the bytes change (mirrors
   `TestActionApprovalSigningBytesBinding`).

> The `refField`/`refBE64`/`cat` helpers already exist in `protocol/v2_signing_test.go`
> (same package `protocol`), so the re-derivation test can reuse them directly — no
> duplication needed.

### 5.4 Verification — tests that must still pass (unchanged)
- `go test ./protocol/...` — all existing protocol vectors + the three new tests.
- `go test ./tui/record/...` — esp. `artifact_proof_test.go`,
  `TestVerifyOldFormatRecordStillValid`, `TestOldArtifactRecordByteIdenticalNotTwoPerson`
  (I1, I2, I9, I10) — unaffected, must stay green.
- `go test ./sealedrecord/...` — `TestFacadeReexportsFullPublicSurface` (I6) — no new
  exported symbol, must stay green.
- `gofmt -l .` empty; `go vet ./...`; `just check-boundary`
  (`TestServerBinaryDoesNotLinkClientCrypto`).
- `cd ciphersigil && go build ./...` (I11) — Pass A changes nothing the consumer sees.

> **Per memory:** run Go tests via the PowerShell tool, one package at a time (the
> Bash tool hangs `go test` on Windows). `go` invocations are ~20 s each here.

### 5.5 Pass A "what we are NOT adding"
No v2 function, no `Role` field, no façade change, no consumer change, no tag *inside*
the pass. (The `v1.9.0` tag is a discrete housekeeping step **after** Pass A is
verified — §4 Q6 — and is itself a tagging action, not a code change.)

---

## 6. Pass B outline (NOT YET BUILT — Netherchat v2 role structure)

Additive only. No existing exported signature, record byte, or proof byte changes.

**Files:**
- `protocol/artifact_signing.go` — add `ArtifactApprovalSigningBytesV2(proposalID,
  artifactHash, approverFpr, nonce, role string)` under tag
  `netherchat/artifact-approval/v2` (Q3). Leave v1 untouched.
- `protocol/artifact_signing_test.go` — add `TestArtifactApprovalSigningBytesV2Vector`
  (frozen + re-derived) and `TestArtifactApprovalV2DiffersFromV1` (I8).
- `tui/record/sealed.go` — add `ApprovalProof.Role` (`omitempty`); per-proof dispatch
  in `verifyArtifactApprovals` (Q3); add `VerifyResult.ArtifactApproverRoles` +
  `VerifiedApprover` + `VerifiedArtifactApproverRoles` accessor (Q4); apply existing
  exclusion/distinctness to the combined set (I10).
- `tui/record/sealer.go` — add a role-aware approval method (e.g.
  `AddArtifactApprovalV2(proposalID, role, pub, sig)`) and a `SigningBytes`-style
  exposure of the v2 preimage (mirroring `EndorsementSigningBytes`) so an ssh-agent
  caller need not import `protocol`. Leave `AddArtifactApproval` (v1) untouched.
- `tui/report/report.go` — role-aware `approverDisplay` (Q4), fallback to roleless.
- `sealedrecord/sealedrecord.go` — **re-export** `VerifiedApprover` and
  `VerifiedArtifactApproverRoles` (I6 — surface guard breaks the build otherwise).
- Tests: extend `tui/record/artifact_proof_test.go` with a role-typed happy path,
  a v1+v2 mixed-bag record, a v2 forged-role-attribution fail-closed, and a
  **byte-identical v1-only** regression (re-assert I2 with the new field present in
  the struct but `omitempty`-absent on v1 proofs).

**Backward-compat (must re-verify I1, I2, I4, I8, I9, I10):** v1 proofs and old
records verify byte-identically; new domain tag isolates v2; role is opaque.

**What Pass B is NOT:** no consumer code, no policy/threshold, no name/signedAt/meaning
in the preimage, no change to `ArtifactApprovers`' existing shape, no `go.mod`/tag
edits inside the pass (tag `v1.10.0` is the discrete step after).

## 7. Pass C outline (NOT YET BUILT — CipherSigil consumer policy + housekeeping)

Consumes the post-Pass-B additive API. See Q5 for the full design and file list.
Summary:
- `internal/record/seal.go` — `Roster` → `map[string]RosterMember{Name, Roles}`;
  preserve `Roster.Name`; add `Roster.HasRole`.
- `internal/record/artifact.go` — add `ArtifactRecordMeetsRoleQuorum(b, roster,
  requiredRoles)` (per-role `verified-as-R ∩ roster-authorizes-R`, all-or-nothing,
  fail-closed, distinct-person across roles per §9); keep `ArtifactRecordIsTwoPerson`.
- `internal/config/…` — role-aware roster format + per-action-class quorum policy
  (mode + `n` or `requiredRoles`).
- Update `Roster` construction/consumption call sites + tests (count-mode tests stay
  green; M3 `validateSealPolicy` unaffected via preserved `Name`).
- `go.mod` — `require` `v1.9.0 → v1.10.0`; keep `replace`.

**What Pass C is NOT:** no Netherchat edits; no change to M3's deliverable workflow;
no role policy in records.

---

## 8. Cross-repo coordination & order of operations (seam protection)

The `replace github.com/salehkreiner/netherchat => ../netherchat` means CipherSigil
builds against Netherchat's working tree at every commit. The sequence below keeps
`cd ciphersigil && go build ./...` (I11) green at **every** intermediate commit.

```
1. Netherchat: Pass A (test-only).            → ciphersigil build: GREEN (nothing changed for consumer)
   Verify:  go test ./protocol/... ./tui/record/... ./sealedrecord/...; gofmt; vet; boundary; ciphersigil go build.
2. Netherchat: tag v1.9.0.                     → housekeeping, no code change.
   CipherSigil: bump go.mod require v1.8.0→v1.9.0 (keep replace). Verify ciphersigil go build + go test.
3. Netherchat: Pass B (purely additive).       → ciphersigil build: GREEN (consumer untouched; new API unused;
                                                   ArtifactApprovers shape unchanged; new fields omitempty).
   Verify:  full Netherchat suite incl. I1/I2/I4/I6/I8/I9/I10; then ciphersigil go build (must still pass).
4. Netherchat: tag v1.10.0 (+ forward-incompat release note).
5. CipherSigil: Pass C (Roster role type, role-typed enforcement, config).
   CipherSigil: bump go.mod require v1.9.0→v1.10.0 (keep replace). Verify ciphersigil go build + go test.
```

**Why the seam never breaks:**
- Pass A changes only Netherchat test files → invisible to the consumer.
- Pass B is additive (new tag, new functions, `omitempty` field, unchanged existing
  exported signatures) → CipherSigil compiles unmodified against it.
- Pass C is isolated to CipherSigil and consumes only already-landed Netherchat API.
- At no step does an existing exported Netherchat symbol the consumer uses change
  shape; `ArtifactApprovers` and `VerifiedArtifactApprovers` are explicitly preserved.

---

## 9. Open questions for you (decide before Pass B)

1. **Distinct-person across roles (SoD core).** Must each required role be filled by a
   **distinct** fingerprint (recommended default — true segregation), or may one
   authorized individual satisfy multiple required roles if the roster authorizes them
   for both? The library will surface all `(fpr, role)` pairs faithfully either way;
   this is a Pass C consumer-policy choice but affects Pass C's test design.
2. **Role vocabulary ownership.** Confirm the role string stays **opaque** to the
   library (consumer defines `qa`/`technical`/`system-owner`/… and any
   canonicalization, e.g. case). Recommended: opaque, consumer-owned — matches
   `Meaning`/`Schema`. Any normalization happens consumer-side.
3. **Roster authorization model.** Confirm a roster member may hold **multiple** roles
   (`Roles []string`), and that authorization is per-(fpr, role) — i.e. signing as a
   role you are not rostered for does **not** count, even with a valid signature
   (recommended; closes the role-layer forgery). 
4. **Tag cadence.** Approve the `v1.9.0` (post-Pass-A) and `v1.10.0` (post-Pass-B)
   sequence and the CipherSigil `require` bumps, or prefer to defer all tagging to one
   release at the end (trades the honesty fix for fewer tags).
5. **Mixed v1/v2 proofs in one proposal.** Confirm a single proposal may legitimately
   carry both roleless (v1) and role-typed (v2) approvals (e.g. a count-mode approver
   plus role-mode approvers). Recommended: allowed; role-mode reads only the role-typed
   subset, count-mode reads the union.

---

*End of plan. Deliverable is this document only — no code, go.mod, build, or tag
changes were made.*
