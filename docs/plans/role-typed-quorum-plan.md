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

## 6. Pass B build spec (BUILD-READY — Netherchat v2 role structure)

> Re-verified against the working tree after Pass A landed (HEAD `18e6142`; v1.9.0
> tagged and **public**). Pass B is **Netherchat-only and purely additive**: it makes
> an approver's *role* expressible in signed bytes and surfaced through verification.
> It does **not** enforce any policy — that is Pass C (§7). CipherSigil compiles
> unmodified against the result (§6.9).

### 6.0 Intent

An approver may sign an artifact approval **with a declared, opaque role** (e.g.
`qa`, `technical`, `system-owner`) under a new domain tag
`netherchat/artifact-approval/v2`. The verifier reconstructs the role-bearing
preimage, and `Verify` surfaces, per proposal, the set of **(fingerprint, role)**
pairs that cryptographically verified — alongside the existing role-agnostic
`ArtifactApprovers` set, which is **left exactly as it is**. v1 proofs and pre-v2
records remain byte-identical.

### 6.1 The two design forks, resolved (analysis + recommendation)

These were the open questions; both are recommended here for sign-off. Everything
else in §6 is settled by the decisions in the task brief (#1 layout, #4 opacity, #5
test placement/style, #6 `omitempty` last field, #7 Sealer ergonomics).

#### Fork #2 — version discriminator: content-gate on `Role != ""` vs. explicit field

**Recommendation: content-gate on `Role != ""`** (no explicit version field).

| Criterion | Content-gate (`Role != ""`) | Explicit field (e.g. `Ver int`) |
| --- | --- | --- |
| v1 byte-identity | **Cleanest:** one `omitempty` field, **zero** populated for v1 → v1 JSON unchanged. | Two new fields (`Ver`+`Role`), both must be `omitempty`/zero on v1; more to keep byte-identical. |
| Verifier dispatch | One branch at the single dispatch point: `if p.Role != "" { v2 } else { v1 }`. | `switch p.Ver` **plus** a cross-field consistency rule (reject `Ver=2,Role==""` and `Ver=0,Role!=""`) — extra fail-closed surface. |
| House idiom | **Matches** `Entry.extended()` (`record.go:117-119`) and the endorsement dispatch (`sealed.go:301-304`): content-gated, no version int. | New idiom for this codebase. |
| Auditor reading raw JSON | A proof either shows `"role":"qa"` (v2) or has no `role` key (v1) — the key's presence *is* the version. | `"ver":2,"role":"qa"` is marginally more self-declaring, but the redundancy invites "why both?" |
| Tamper safety | All directions fail closed: relabel/strip/add a role and the reconstructed preimage no longer matches the signature (v1 and v2 preimages differ by tag **and** trailing `field(role)`). | Same crypto, but the redundant `Ver` can disagree with `Role`, so it adds a consistency check that must itself be correct. |

**On "empty-role v2 is unrepresentable":** this is **not a loss** for role-typed
quorum. A role is, by definition (decision #1, SoD use case), a meaningful non-empty
function name. An approval whose role is the empty string carries **no** segregation
information that a v1 roleless approval does not already express — so forbidding it
removes a degenerate, redundant state rather than a useful one. Content-gating turns
"a v2 proof's role must be non-empty" into a structural invariant for free.

#### Fork #3 — `VerifyResult` role surface: shape and dedup key

**Recommendation: a parallel, `omitempty` map of (fingerprint, role) pairs, deduped
by the PAIR.** Exact Go type:

```go
// VerifiedApprover is one cryptographically-verified role-typed approval: the
// approver's fingerprint and the opaque role they signed with. (Library attaches no
// meaning to Role; the consumer owns the vocabulary — decision #4.)
type VerifiedApprover struct {
    Fingerprint string `json:"fingerprint"`
    Role        string `json:"role"`
}

// On VerifyResult, additive and omitempty (absent on records with no v2 proofs):
ArtifactApproverRoles map[string][]VerifiedApprover `json:"artifact_approver_roles,omitempty"`
```

- **Dedup by (fpr, role), not by fpr.** Tie to the distinctness decision (configurable,
  default distinct, relaxable so one authorized person may fill multiple roles when
  relaxed): the consumer (Pass C) must be able to ask *both* "is required role R
  covered by an authorized fpr?" and "are the fprs covering the required roles
  distinct from each other?". If the same person legitimately signs as **two** roles
  (Alice as `qa` **and** as `technical`), only **per-(fpr,role)** preserves both pairs;
  **per-fpr would collapse them and destroy information the consumer cannot recover**,
  pre-deciding the distinctness question the library is supposed to leave open. A
  duplicate *pair* (Alice signs `qa` twice) still collapses to one — that is real
  de-duplication, not information loss.
- **Roleless (v1) approvers do NOT appear in `ArtifactApproverRoles`** (read's
  recommendation, confirmed). They have no signed role; surfacing them with `Role:""`
  would pollute the role map and force the consumer to filter empties. They remain in
  `ArtifactApprovers` only.
- **A v2 approver appears in BOTH maps** (deliberate): its fingerprint joins the
  role-agnostic `ArtifactApprovers` distinct set **and** its pair joins
  `ArtifactApproverRoles`. This keeps CipherSigil's existing **count-mode**
  (`ArtifactRecordIsTwoPerson`/`VerifiedArtifactApprovers`) counting role-typed
  approvers too, so Pass C can add role-mode *beside* count-mode without changing
  count-mode's results. There is no existing record with v2 proofs, so no prior
  `ArtifactApprovers` content changes.
- **Accessor** (nil-safe, mirrors `VerifiedArtifactApprovers`):
  `VerifiedArtifactApproverRoles(res *VerifyResult, proposalID string) []VerifiedApprover`.

### 6.2 v2 preimage spec (exact bytes)

New function in `protocol/artifact_signing.go` (same file as v1, `…V2` suffix — house
convention per `action_signing.go`):

```
func ArtifactApprovalSigningBytesV2(proposalID, artifactHash, approverFpr, nonce, role string) []byte

Layout (artifact-approval v2):

    field("netherchat/artifact-approval/v2")
      || field(proposal_id) || field(artifact_hash) || field(approver_fpr) || field(nonce)
      || field(role)

where field(b) = uint64-big-endian(len(b)) || b.   // role is length-prefixed like every other field
```

The four v1 fields are emitted **verbatim and in the same order**; `field(role)` is
appended **last** (decision #1). New tag only; v1 (`…/v1`) function untouched.

**Frozen byte-vector (self-checked, not asserted).** Inputs
`ArtifactApprovalSigningBytesV2("a3f9", "deadbeef", "SHA256:abc", "nonce0", "qa")`.
The four middle fields are byte-for-byte the **already-verified** fragments from the
Pass A v1 vector; only the tag and the new `role` field are new, and both were
self-checked with `xxd`:

- tag `"netherchat/artifact-approval/v2"` → length 31 (`0x1f`); hex
  `6e6574686572636861742f61727469666163742d617070726f76616c2f7632`
  (identical to the v1 tag except the final byte `31`→`32`, i.e. `v1`→`v2` — confirmed
  via `printf … | xxd -p`).
- role `"qa"` → length 2; hex `7161` (confirmed via `xxd`).

Full expected preimage (the frozen `const want` for the new test):

```
000000000000001f 6e6574686572636861742f61727469666163742d617070726f76616c2f7632  field("netherchat/artifact-approval/v2")
0000000000000004 61336639                                                          field("a3f9")
0000000000000008 6465616462656566                                                  field("deadbeef")
000000000000000a 5348413235363a616263                                              field("SHA256:abc")
0000000000000006 6e6f6e636530                                                      field("nonce0")
0000000000000002 7161                                                              field("qa")
```

The test's `const want` MUST be written as the `+`-joined per-field hex fragments
**exactly as the table above lists them** (Pass A `artifact_signing_test.go` style:
one `"len" + "bytes"` pair per line with a `// field(...)` comment), NOT as one
monolithic string — each fragment stays independently legible and the four middle
pairs are copy-verifiable against the Pass A v1 vector. The test MUST **also** include
an independent `refField`/`cat` re-derivation (decision #5) asserting equality with
both the const and the production output, so a field reorder is caught even if the
const were edited to match a drifted function.

### 6.3 Proof model & verifier dispatch

**Struct change** (`tui/record/sealed.go`, current `ApprovalProof` at lines 67-71) —
append one field, decision #6:

```go
type ApprovalProof struct {
    ApproverFpr string `json:"approver_fpr"`
    ApproverKey string `json:"approver_key"`
    Sig         string `json:"sig"`
    Role        string `json:"role,omitempty"` // NEW: opaque signed role; absent ⇒ v1 proof (content-gate, fork #2)
}
```

**Coexistence:** a single `ArtifactApprovals[pid]` bag may hold a mix of v1 (no role)
and v2 (role) proofs. Dispatch is **per proof**, content-gated on `p.Role`.

**Where the dispatch slots in.** The current loop in `verifyArtifactApprovals()`
(`tui/record/sealed.go:373-391`):

```go
distinct := make(map[string]bool)
for _, p := range proofs {
    key, err := base64.StdEncoding.DecodeString(p.ApproverKey)
    if err != nil || len(key) != ed25519.PublicKeySize { return nil, … }
    if crypto.Fingerprint(ed25519.PublicKey(key)) != p.ApproverFpr { return nil, … } // key→fpr binding (I7/I9)
    sig, err := base64.StdEncoding.DecodeString(p.Sig)
    if err != nil { return nil, … }
    preimage := protocol.ArtifactApprovalSigningBytes(pid, m.ArtifactHash, p.ApproverFpr, m.Nonce)   // ← single dispatch point
    if !ed25519.Verify(ed25519.PublicKey(key), preimage, sig) { return nil, … }
    distinct[p.ApproverFpr] = true
}
```

The **only** change to the loop body is the one `preimage :=` line, which becomes a
content-gated branch (shape of the change; not committed code):

```go
    var preimage []byte
    if p.Role != "" {
        preimage = protocol.ArtifactApprovalSigningBytesV2(pid, m.ArtifactHash, p.ApproverFpr, m.Nonce, p.Role)
    } else {
        preimage = protocol.ArtifactApprovalSigningBytes(pid, m.ArtifactHash, p.ApproverFpr, m.Nonce)
    }
    if !ed25519.Verify(ed25519.PublicKey(key), preimage, sig) { return nil, … }
    distinct[p.ApproverFpr] = true
    if p.Role != "" { rolePairs = append(rolePairs, VerifiedApprover{p.ApproverFpr, p.Role}) } // collect v2 pairs
```

`rolePairs` is accumulated per proposal, then — **after** the same author/proposer
exclusion the roleless set already applies (`sealed.go:394-400`) — deduped by
(fpr, role) and sorted into `ArtifactApproverRoles[pid]`. `verifyArtifactApprovals()`
returns **two** maps now (the existing `map[string][]string` and the new
`map[string][]VerifiedApprover`); `Verify` populates both result fields. Everything
else in the function (artifact-entry indexing, nonce requirement, key→fpr binding,
orphan/duplicate-proposal rejection) is **unchanged**.

### 6.4 Surfacing & rendering

- `VerifyResult` gains `ArtifactApproverRoles` (type/shape per §6.1, fork #3);
  `ArtifactApprovers` (`sealed.go:203`) is **untouched** in name, type, JSON tag, and
  population.
- `Verify` (`sealed.go:321-330`) populates `res.ArtifactApproverRoles` from the second
  returned map, guarded by `len(...) > 0` exactly like `ArtifactApprovers`, so it stays
  absent (omitempty) on records with no v2 proofs.
- **Report** (`tui/report/report.go`, `approverDisplay` at lines 82-110): prefer the
  role-attributed display when `VerifiedArtifactApproverRoles(res, pid)` is non-empty —
  render each as `"<name> — <role>"` (full report appends the short fpr, matching the
  existing `withFpr` path), falling back to the current roleless rendering when a
  proposal has only v1 proofs. Presentational only; no policy, no verdict.

### 6.5 Sealer + preimage-exposer API (decision #7)

Additive methods on `Sealer` (`tui/record/sealer.go`); v1 `AddArtifactApproval`
(lines 171-196) left untouched:

```go
// Exposer: returns the exact v2 preimage to sign, WITHOUT importing protocol.
// Mirrors EndorsementSigningBytes (sealer.go:102-104) but — unlike it — must look the
// artifact entry up (artifactMetaByProposal) for the signed artifact_hash + nonce, so
// it returns an error when there is no matching proposal / no nonce.
func (s *Sealer) ArtifactApprovalSigningBytesV2(proposalID, role string, pub ed25519.PublicKey) ([]byte, error)

// Records a verified role-typed approval. Mirrors AddArtifactApproval: reconstructs the
// v2 preimage from the entry's signed body + role, verifies sig, then appends
// ApprovalProof{ApproverFpr, ApproverKey, Sig, Role: role}. Returns the approver fpr.
func (s *Sealer) AddArtifactApprovalV2(proposalID, role string, pub ed25519.PublicKey, sig []byte) (string, error)
```

(The `([]byte, error)` return on the exposer is a deliberate, documented divergence
from `EndorsementSigningBytes`, which needs no lookup and cannot fail.)

### 6.6 Façade re-exports (`sealedrecord/sealedrecord.go`) — I6

The surface guard (`TestFacadeReexportsFullPublicSurface`) scans `tui/record`,
`tui/report`, `tui/attest` for **top-level** exported decls and fails the build if any
is not aliased. Exactly **two** new symbols are top-level and therefore MANDATORY to
add:

| New symbol | Kind | Façade action |
| --- | --- | --- |
| `VerifiedApprover` | type (in `tui/record`) | add `VerifiedApprover = record.VerifiedApprover` to the `type (…)` block (`sealedrecord.go:48-60`) |
| `VerifiedArtifactApproverRoles` | func (in `tui/record`) | add `VerifiedArtifactApproverRoles = record.VerifiedArtifactApproverRoles` to the `var (…)` block (`sealedrecord.go:85-99`) |

Everything else rides along on **existing** aliases and needs **no** re-export:
`ApprovalProof.Role` (field on aliased `ApprovalProof`),
`VerifyResult.ArtifactApproverRoles` (field on aliased `VerifyResult`),
`Sealer.AddArtifactApprovalV2` / `Sealer.ArtifactApprovalSigningBytesV2` (methods on
aliased `Sealer`). **`protocol.ArtifactApprovalSigningBytesV2` is NOT re-exported** —
the surface guard does not scan `protocol`, the v1 function is likewise not in the
façade, and the Sealer exposer (§6.5) gives external signers the preimage without
importing `protocol`. (If we later choose to expose it on the façade for symmetry,
that is optional, not guard-mandated.)

### 6.7 Invariant preservation proof

| Inv | Property | How Pass B preserves it | Proof (test) |
| --- | --- | --- | --- |
| **I1** | old v1 records verify VALID | Old records have no `artifact_approvals`; the `if len(r.ArtifactApprovals) > 0` gate (`sealed.go:321`) skips the whole block. No change to the chain/seal path. | `TestVerifyOldFormatRecordStillValid` |
| **I2** | old artifact records byte-identical | Old records carry no proofs; nothing in `ArtifactMeta` changes (role lives on the **proof**, not the meta). | `TestOldArtifactRecordByteIdenticalNotTwoPerson` |
| **I2′** | **v1-proof** records byte-identical | `Role` is `omitempty` and **never set** by v1 `AddArtifactApproval`, so a v1 proof serializes with no `role` key, byte-for-byte as before. | **NEW** `TestV1ArtifactProofByteIdenticalWithRoleField` (the read found this property currently **unpinned** — only the no-proofs case was tested) |
| **I4** | v2 follows content-gated new-tag precedent | New tag `…/v2`; layout is v1 fields + `field(role)`; dispatch mirrors `Entry.extended()`. | reuse-of-precedent; covered by I8 test |
| **I5/forward-incompat** | a v2 proof makes a **pre-v2** verifier reject the **whole record** | `Parse` uses `DisallowUnknownFields()` (`sealed.go:168`), which applies **recursively** — an old `ApprovalProof` without a `role` field rejects any proof carrying `"role"`. Record-level reject, not field-ignore. | `TestRoundTripDisallowUnknownFields` (top-level only) **+ NEW** `TestParseRejectsUnknownFieldInProof` (the read found **no test asserts the nested case**; this pins it by injecting a bogus key inside a proof and asserting `Parse` errors) |
| **I6** | façade mirrors full surface | Add the two aliases in §6.6. | `TestFacadeReexportsFullPublicSurface` (fails build if missing) |
| **I7** | SSH-wire fingerprint dialect intact | v2 verify still binds key→fpr via `crypto.Fingerprint` (`sealed.go:379`); role never touches fingerprinting; no new dialect. | `TestSSHKeyFileFingerprintMatchesSSH` + the in-loop key→fpr check |
| **I8** | domain-tag separation | `netherchat/artifact-approval/v2` is unique (grep: appears only in the plan doc today); v2 preimage ≠ v1 even structurally. | **NEW** `TestArtifactApprovalV2DiffersFromV1` (mirrors `TestRecordV2DiffersFromV1`): assert `v1(p,h,f,n) != v2(p,h,f,n,"qa")` |
| **I9** | fail-closed on bad proofs | The single dispatch only changes which preimage is reconstructed; a wrong/forged/relabeled v2 proof fails `ed25519.Verify` exactly as v1 does; key→fpr binding unchanged. | **NEW** fail-closed v2 tests (§6.8) |
| **I10** | author/proposer exclusion + distinctness | Roleless set keeps fpr-string exclusion (`sealed.go:396`) unchanged; the role map applies the **same** exclusion before emitting pairs, and dedups by (fpr, role). | extend `TestArtifactProofAuthorAndProposerExcluded` for a v2 pair; **NEW** dedup-by-pair test |

### 6.8 New tests (build-ready list)

- **`protocol/v2_signing_test.go`** (house location for v2 vectors, decision #5):
  `TestArtifactApprovalSigningBytesV2Vector` — frozen `const want` (§6.2) **and** a
  `refField`/`cat` re-derivation cross-check; `TestArtifactApprovalV2DiffersFromV1`
  (I8). *(Correction vs. the earlier outline, which named `artifact_signing_test.go`;
  v2 vectors live in `v2_signing_test.go` per house convention, but we keep the
  frozen-hex anchor that the other v2 vectors omit.)*
- **`tui/record/artifact_proof_test.go`**: role-typed happy path (one v2 proof →
  surfaces one `(fpr, role)` pair, fpr also in `ArtifactApprovers`); v1↔v2 mixed bag in
  one proposal (both verify; only the v2 one appears in the role map); same-fpr-two-roles
  (both pairs surface — pins per-(fpr,role) dedup); duplicate identical pair collapses to
  one; v2 author/proposer excluded from the role map; **I2′** byte-identical v1-proof
  record; fail-closed: v2 proof whose `Role` was tampered after signing, v2 proof signed
  over the **v1** preimage (role added to JSON), v1 proof with a role added (dispatch flips,
  verify fails), v2 key→fpr mismatch.
- **`tui/record/sealed_test.go`**: `TestParseRejectsUnknownFieldInProof` (nested
  `DisallowUnknownFields`).

### 6.9 Seam confirmation & order of operations

**CipherSigil compiles unmodified against post-Pass-B** because Pass B is additive and
touches no symbol the consumer references:
- `ArtifactApprovers`, `VerifiedArtifactApprovers`, `VerifiedArtifactApprovals`,
  `ArtifactOf`, `KindArtifact`, `ArtifactMeta.ProposalID`, `AddArtifactApproval`,
  `Verify`, `Parse` — **all unchanged in signature and shape**.
- New struct fields are additive; CipherSigil never constructs `sealedrecord.ApprovalProof{}`
  or `sealedrecord.VerifyResult{}` (verified by grep — its only `VerifyResult{…}` literals
  are its **own** unrelated types), and builds proofs via `Sealer.AddArtifactApproval`, so
  field additions are transparent.
- The new role surface is simply unused by the consumer until Pass C.

**Order of operations (seam stays green at every commit):**
1. Land Pass B in Netherchat (additive only). Run the full Netherchat suite incl.
   I1/I2/I2′/I5/I6/I8/I9/I10, `gofmt`, `vet`, boundary guard.
2. **Verify `cd ../ciphersigil && go build ./...` (and `./internal/...`) is GREEN** —
   the consumer is unmodified and must still build against the replace-linked tree.
3. Tag **`v1.10.0`** with the forward-incompat release note (records carrying
   `artifact-approval/v2` proofs fail to parse on verifiers < v1.10.0 — §4 Q6).
4. Pass C (CipherSigil) consumes the role surface and bumps `require` → `v1.10.0`.

### 6.10 What Pass B is NOT adding (anti-bloat)

- **No consumer policy / threshold / quorum logic** — count- and role-mode enforcement
  is Pass C.
- **No roster changes** — `Roster map[string]string` and the `RosterMember{Name,Roles}`
  change are Pass C; Pass B does not touch CipherSigil at all.
- **No required-role config** and **no distinctness enforcement** — the library
  surfaces all verified `(fpr, role)` pairs faithfully; *deciding* which roles are
  required and whether they must be distinct people is Pass C.
- **No `name`, `signed_at`, or `meaning`** in the v2 preimage (decision #1) — role is
  the only new field; the approval act stays implicit ("approved"), names stay
  roster-resolved by the consumer, timestamps stay in `ArtifactMeta`.
- **No new on-disk record version label** — an approvals-bearing record is already
  `FormatVersionV2` (`recordVersion`, `sealed.go:148-158`); the version gate keeps
  accepting it.
- **No `go.mod` / tag edits inside the pass** — `v1.10.0` is the discrete step after.

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
