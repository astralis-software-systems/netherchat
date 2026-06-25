# Role-Typed N-of-M Quorum — Implementation Plan

> **Status:** Passes A and B are **BUILT and shipped** (Netherchat `v1.9.0` and
> `v1.10.0`, public tags). Pass C (CipherSigil consumer enforcement) is **BUILT** per
> §7 — role-typed quorum primitive, role-carrying roster, config, and `go.mod`
> honesty bump, committed local-only on `master`. The §1–§6 design text is retained
> as the build record.
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

## 7. Pass C build spec (BUILD-READY — CipherSigil consumer policy + housekeeping)

> Re-verified against the codebase by a dedicated read (CipherSigil HEAD `a32d28d`,
> working tree clean, branch `master`, **no git remote**; Netherchat `main` = `v1.10.0`
> = `059b3f1`, which the `replace => ../netherchat` already compiles the consumer
> against). This section **supersedes** the pre-read outline. Where it contradicts the
> earlier Q5 sketch, the read is authoritative and the correction leads. Pass C is
> **CipherSigil-only** (`C:\Users\saleh\ciphersigil` — the Go/Wails app with
> `internal/record|workflow|config`, **not** the UI prototype) and consumes only the
> already-landed v1.10.0 role surface; it touches no Netherchat code.

### 7.0 Corrections from the read (these reframe the whole pass)

The pre-read outline assumed things the codebase does not contain. Build to the
corrected picture:

| # | Pre-read assumption | Ground truth (read) | Consequence for Pass C |
| --- | --- | --- | --- |
| **R1** | Required-roles "attach to an existing action-class / risk-tier / PROD gate." | **No such concept exists anywhere in CipherSigil.** No action-class, risk-tier, or `target=PROD → HOLD` gate; the workflow is a flat phase machine (`PhaseIngested → PhaseDrafted → PhaseApproved/PhaseRejected → PhaseSealed`), and the only "risk class" string is an aspirational comment in `internal/record/artifact.go:32`. | Action-class is **100% net-new**. Pass C ships a single `requiredRoles` policy now; the *config shape* is designed so a class-keyed dimension is a later **additive** extension (§7.4). |
| **R2** | Pass C enforcement runs in the app. | **Nothing Pass C builds will run.** The workflow `Engine` and the existing `ArtifactRecordIsTwoPerson` are **both unmounted** — `app.go:64-66` states the engine is mounted "in a later one," and `startLocalAPI()` wires only the single-signer Ingest path (`core.NewService` + `api.NewServer`). `config.Roster()` and `ArtifactRecordIsTwoPerson` have **zero non-test callers**. | Pass C lands a **tested-but-unmounted** library primitive, exactly as count-mode already lives. App-wiring is a **named future pass** (§7.10), not planned here. |
| **R3** | Changing `Roster` is the architectural "biggest ripple." | The ripple is **contained to library + test code, with zero composition-root change** (nothing constructs a `Roster` in the running app). Preserving `Name(fpr)(string,bool)` keeps **every consumer call site compiling untouched**; only **construction** sites change. | The `Roster` type change is mechanical and test-heavy (§7.3), not a wiring refactor. `internal/workflow/workflow.go` needs **no edit at all**. |
| **R4** | `go.mod` is one hop from honest. | `require … netherchat v1.8.0` predates **even the v1.9.0 API the consumer already uses** (`VerifiedArtifactApprovers`, `ArtifactApprovers`, `ArtifactMeta.ProposalID`); only the `replace` makes it build. | go.mod honesty is a **two-hop** fix: `v1.8.0 → v1.10.0` (§7.6). |
| **R5** | `TestLoadRosterValid` breaks when `approverEntry` gains roles. | **Refinement: it does not.** It calls `loadRoster` + asserts `r.Name(fpr)`; with `Name` preserved and `roles` an `omitempty` field absent from its fixture JSON, it compiles and passes unchanged. The config-side test work is **purely additive** (new role-loading tests). | No forced edit to existing config tests; only new tests (§7.7). |

### 7.1 Scope statement & non-goals

**In scope:** the role-typed enforcement *primitive* and its config + roster
substrate, with full tests — **unmounted**, mirroring how `ArtifactRecordIsTwoPerson`
already exists. Specifically: a role-mode enforcement function, a role-carrying
`Roster`, a forward-compatible config shape, the new role-loading path, and the
`go.mod` honesty bump.

**Explicit non-goals (anti-bloat — see also §7.9):**
- **No `app.go` / composition-root changes; no Engine mounting.** `startLocalAPI`
  stays as-is.
- **No action-class policy table** (R1) — single `requiredRoles`, config shaped to
  grow one additively.
- **No change to M3** (`internal/workflow`: `Decide`/`Seal`/`validateSealPolicy`).
  It uses `roster.Name` for membership only and keeps compiling via the preserved
  accessor; it reads neither `ArtifactApprovers` nor `ArtifactApproverRoles`.
- **No activation of `ErrDuplicateApprover`** (still the deferred N-of-M guard in
  `Decide`; KNOWN_LIMITATIONS §4). Role-mode distinctness is a *new* check over the
  role surface, unrelated to it.
- **No Netherchat edits; no role policy baked into records.**

### 7.2 The role-mode enforcement primitive (`internal/record/artifact.go`)

**Recommended signature** (refines the outline's bare `requiredRoles []string`,
because distinctness must ride along and the policy must be forward-compatible — a
bare `bool` would be call-site-illegible and a bare slice can't carry the toggle):

```go
// RoleQuorum is the consumer's role-typed SoD policy for ONE evaluation. The zero
// value is the safe SoD default: a DISTINCT fingerprint per required role.
type RoleQuorum struct {
    RequiredRoles     []string // each must be filled by ≥1 verified, roster-AUTHORIZED approver
    AllowSharedPerson bool     // zero=false ⇒ distinct person per role; true relaxes it (deliberate, visible)
}

func ArtifactRecordMeetsRoleQuorum(b []byte, roster Roster, policy RoleQuorum) error
```

`RoleQuorum`'s zero value being the strict default is intentional: a config that
forgets the toggle gets *more* segregation, never less. (`AllowSharedPerson` names the
*relaxation*, so the unsafe state is the one you must spell out.) The struct is the
config-resolution boundary (§7.4) and can grow fields without changing this contract.

**Full logic, in order (fail-closed at every step):**

1. **Arg guard (before any parse):** `len(policy.RequiredRoles) == 0` → error. An
   empty required-role set is the *absence* of a policy, and "≥1 of each of zero
   roles" is vacuously true for *every* proposal — a silent universal pass. Reject it,
   exactly as count-mode rejects `n < 1` (`artifact.go:111-113`). Also reject a
   `RequiredRoles` containing an empty/whitespace-only or duplicate entry (defensive;
   the loader §7.4 also rejects these, but the primitive must not trust its caller).
2. **Parse → verify → validity:** `Parse(b)`; `sealedrecord.Verify(rec)`; fail on
   parse error, verify error, or `!res.Valid` — byte-identical posture to count-mode
   (`artifact.go:114-124`).
3. **Per artifact proposal** (each `KindArtifact` entry, via `ArtifactOf`; an entry
   with no `ProposalID` fails closed, as today): read the verified role pairs
   `pairs := sealedrecord.VerifiedArtifactApproverRoles(res, pid)` (`[]VerifiedApprover`,
   already author/proposer-excluded and `(fpr,role)`-deduped **by the library**, Pass B
   — Pass C re-excludes nothing). For each required role `R`, build the authorized set
   `F_R = { p.Fingerprint : p ∈ pairs, p.Role == R, roster.HasRole(p.Fingerprint, R) }`.
   This is the **role-layer generalization of count-mode's `verified ∩ roster`**:
   `verified-as-R ∩ roster-authorizes-R` (§7.7). If any `F_R` is empty → fail closed
   naming **(proposal, role)** and enumerating the verified pairs present (§7.5
   ergonomics).
4. **Distinctness:**
   - `AllowSharedPerson == false` (default): require an assignment of a **distinct**
     fingerprint to each required role — i.e. a system of distinct representatives
     across the `F_R` sets. **Build note (correctness):** this is bipartite matching,
     **not** a naive "pick one per role then check pairwise-distinct" — greedy picking
     can fail when a matching exists (e.g. required `{qa, technical}`, `F_qa={Alice,Bob}`,
     `F_technical={Alice}`: greedy may take `qa→Alice` and then deadlock). Use a small
     matching / Hall's-condition check (role counts are tiny — 2-4). If no perfect
     matching exists → fail closed naming the proposal and the unsatisfiable role set.
   - `AllowSharedPerson == true`: skip the matching; each `F_R` non-empty suffices (one
     authorized person may cover several roles).
5. **All-or-nothing across proposals:** every artifact proposal must clear the bar
   (one approved artifact cannot vouch for an unapproved sibling) — same as count-mode
   (`artifact.go:126-140`).
6. **No artifact proposals at all:** reuse `ErrNoArtifactApprovals` (valid record,
   nothing offline-provable — the exact count-mode sentinel, `artifact.go:141-143`).

The **only** thing Pass C adds on top of the library's guarantees is the cross-role
distinct-person rule (step 4) and the `HasRole` authorization filter (step 3, `F_R`):
author/proposer exclusion and `(fpr,role)` dedup are already absolute upstream (I10,
Pass B `dedupApproverRoles`).

**Code structure — recommendation: shared private core + two thin public entries.**
Count-mode and role-mode share ~80% of the body (parse → verify → `!Valid` →
iterate `KindArtifact` proposals → all-or-nothing → `ErrNoArtifactApprovals`); they
differ **only** in the per-proposal predicate. Extract the skeleton:

```go
// eachArtifactProposal owns the mode-agnostic, security-critical skeleton; check
// supplies the mode-specific per-proposal predicate (nil ⇒ this proposal passes).
func eachArtifactProposal(b []byte, check func(pid string, res *ParsedVerifyResult) error) error
```

Both `ArtifactRecordIsTwoPerson` and `ArtifactRecordMeetsRoleQuorum` keep their own
cheap arg guards (`n<1` / empty-`RequiredRoles`) and then delegate, each passing a
closure. **Recommended over two independent siblings** because the load-bearing,
must-be-identical part is precisely the **fail-closed skeleton** — making parity
*structural* (write-once) is safer for a compliance primitive than two functions that
must independently maintain identical posture. The honest risk — refactoring the
already-shipped, mutation-pinned count-mode function — is bounded: the refactor is
**behavior-preserving** (same public signature, same error wording), and the six
existing count-mode tests (§7.7) are the safety net. If any of them go red during the
refactor, the **refactor** is wrong, not the test. The coupling is limited to genuinely
shared concerns: the predicate is fully mode-specific, so role logic cannot leak into
count-mode and vice versa. (If, at build time, the closure seam proves to obscure
count-mode's error messages, fall back to two siblings with a shared doc-comment
checklist — the parity is the requirement, the mechanism is not.)

### 7.3 The `Roster` type change & exact blast radius (`internal/record/seal.go`)

```go
// Roster authorizes a fingerprint as a named person AND for a set of opaque roles.
type Roster map[string]RosterMember

type RosterMember struct {
    Name  string   // operator-pinned printed name (unchanged role from today)
    Roles []string // functions this fingerprint is AUTHORIZED for, e.g. {"qa","technical"}
}

// Name is preserved verbatim in signature so every existing consumer keeps compiling.
func (r Roster) Name(fpr string) (string, bool) { m, ok := r[fpr]; return m.Name, ok }

// HasRole reports whether fpr is rostered AND explicitly authorized for role.
// No implicit authorization: a rostered member with role not listed ⇒ false.
func (r Roster) HasRole(fpr, role string) bool
```

`HasRole` closes the role-layer forgery: a valid signature "as QA" from a fingerprint
the roster does **not** authorize for QA must **not** count. There is **no**
"rostered ⇒ any role" default — that would re-open the forgery one level up.

**Source files that change vs. compile unchanged (read-confirmed):**

| File | Change? | Why |
| --- | --- | --- |
| `internal/record/seal.go` | **EDIT** | type `Roster` (line 275), `Name` body (278-281), **add** `RosterMember` + `HasRole`. |
| `internal/record/artifact.go` | **EDIT** | add `RoleQuorum`, `ArtifactRecordMeetsRoleQuorum`, `eachArtifactProposal`, a `recognizedApproversByRole`-style helper; keep `ArtifactRecordIsTwoPerson`. |
| `internal/config/config.go` | **EDIT** | `approverEntry` gains `roles`; new quorum config + loader; the one construction line `roster[fpr] = name` (236) → `RosterMember{...}` (§7.4). |
| `internal/workflow/workflow.go` | **NO EDIT** | only *consumes* `roster.Name` (303, 398, 537, 544) — preserved signature ⇒ compiles unchanged. Field/param type refs (219, 240) resolve to the new type for free. |
| `internal/config/roster_test.go` | **NO EDIT** | uses `loadRoster` + `r.Name` only; no `Roster{}` literal (R5). |

**Construction sites that change (compile-only, mechanical wrap):**
- `internal/record/artifact_test.go` — the **6** `record.Roster{fpr: "Name"}` literals
  at lines **122, 159, 213, 234, 257, 313** → `record.Roster{fpr: record.RosterMember{Name: "Name"}}`
  (count-mode tests need only `Name`; same values, same assertions — see §7.7).
- `internal/workflow/workflow_test.go` — `rosterFor` helper (lines **145-146**:
  `r[id.Fingerprint()] = id.Name()` → `= record.RosterMember{Name: id.Name()}`) and the
  literal at **736-738** (wrap each value in `RosterMember{Name: …}`).
- `internal/config/config.go:236` — the loader build line (§7.4).

**Zero production-wiring change:** `app.go`, `internal/core`, `internal/api`,
`internal/apiclient`, `internal/repository`, `internal/bundle`, `internal/archive`,
`internal/cipherbond` reference `Roster` **nowhere**. The whole ripple is the three
edited source files + the test literals above.

### 7.4 Config shape (action-class-ready forward-compat) (`internal/config/config.go`)

Today `file` carries `signal_key`, `cipherbond_archive_signer`, `approvers[]{name,
fingerprint}`. Extend additively:

```go
type file struct {
    SignalKey               string            `json:"signal_key"`
    CipherBondArchiveSigner string            `json:"cipherbond_archive_signer,omitempty"`
    Approvers               []approverEntry   `json:"approvers,omitempty"`
    ArtifactQuorum          *quorumConfig     `json:"artifact_quorum,omitempty"` // NEW
}

type approverEntry struct {
    Name        string   `json:"name"`
    Fingerprint string   `json:"fingerprint"`
    Roles       []string `json:"roles,omitempty"` // NEW: authorized functions (opaque)
}

// quorumConfig is the forward-compat envelope. Today only `default` is read; a
// `classes` map is a LATER ADDITIVE key (commented, not built — R1) that needs no
// change to RoleQuorum or to ArtifactRecordMeetsRoleQuorum.
type quorumConfig struct {
    Default *roleQuorumConfig `json:"default,omitempty"`
    // FUTURE (additive): Classes map[string]roleQuorumConfig `json:"classes,omitempty"`
}

type roleQuorumConfig struct {
    RequiredRoles     []string `json:"required_roles"`
    AllowSharedPerson bool     `json:"allow_shared_person,omitempty"`
}
```

On-disk example:

```json
{
  "signal_key": "…hex…",
  "approvers": [
    {"name": "Dr. Bob", "fingerprint": "SHA256:…", "roles": ["qa", "technical"]},
    {"name": "Sam Owner", "fingerprint": "SHA256:…", "roles": ["system-owner"]}
  ],
  "artifact_quorum": {
    "default": { "required_roles": ["qa", "technical", "system-owner"], "allow_shared_person": false }
  }
}
```

**Why this is the forward-compat shape (R1):** the enforcement function takes a
resolved `RoleQuorum`. *Where* that comes from is a pure config concern — today the
loader returns `default`; tomorrow a `classes["prod-deploy"]` lookup returns a
different one. Adding the `classes` key changes neither `RoleQuorum` nor
`ArtifactRecordMeetsRoleQuorum`. The class *selector* (what binds a record/action to a
class) is part of the future pass, not now.

**Loaders & fail-closed rules** (mirror the three-state `ArchiveSigner` precedent,
`config.go:138-169`, but applied to each value's real semantics):

- **Roster (role-carrying):** extend `loadRoster` to build `RosterMember{Name, Roles}`.
  Keep the existing loud guards (missing name/fpr; duplicate fpr; duplicate name).
  **Add:** reject an empty/whitespace-only role string and a duplicate role within one
  approver's `roles` (loud, not silently deduped — ambiguity in a compliance roster
  fails closed). Absent file / absent `approvers` → empty roster (unchanged; role-mode
  then fails closed because every `HasRole` is false → every required role unmet).
- **Quorum policy** — a new `RoleQuorumPolicy()` / `loadRoleQuorum(path)` returning
  `(record.RoleQuorum, error)`. Three states, but note its benign state differs from
  the archive pin's:
  - **ABSENT** (`artifact_quorum` or `default` missing) → a **distinct loud "not
    configured" sentinel** (e.g. `ErrNoRoleQuorum`), **not** a benign TOFU. The archive
    pin has a *safe* degraded mode (store VALID, loudly marked unverified); a
    required-role policy has **none** — "no required roles" must never silently mean
    "everything passes," and inventing a default role set is forbidden (honesty, below).
  - **PRESENT well-formed** → `(policy, nil)`.
  - **PRESENT malformed** (empty `required_roles`, empty/whitespace/duplicate role
    string) → loud fail-closed error, distinct from "not configured."

**Honesty constraints (load-bearing):**
- **No implicit authorization** — `HasRole` false unless the role is explicitly listed
  for that fingerprint. Never "rostered ⇒ any role."
- **No speculative default required-role set** — there is no real SOP today, so baking
  in a default (`["qa","technical",…]`) would be fabricating policy. Mirror
  `MinArtifactApprovers`'s stance (`artifact.go:23-36`): the requirement is a
  config-supplied value, not a hardcoded one; absent config fails closed, it does not
  invent a quorum.
- Role authorization is **operator-pinned** in `approvers[].roles`, exactly as names
  are operator-pinned today — real, configurable data, not synthesized.

### 7.5 Role-string canonicalization — analysis & recommendation (decision C5)

Three independently operator-authored string sets must agree for a match: the **signed
role** (in the v2 proof, surfaced verbatim as `VerifiedApprover.Role` — the library
**never** normalizes it, `protocol/artifact_signing.go:40-44`), the **roster's
authorized roles** (`approvers[].roles`), and the **config's required roles**
(`required_roles`).

| | **A — exact byte-for-byte match (recommended)** | **B — consumer canonicalization (trim + case-fold)** |
| --- | --- | --- |
| Auditability | **Highest:** what was signed *is* what is compared. An auditor reads the proof's `role`, the config's `required_roles`, and the roster's `roles` and confirms the match by inspection — no hidden transform in the trust path. | A normalization sits between "what was signed" and "what was enforced." `"QA"` required vs `"qa"` signed "match" only if the auditor knows the (security-relevant) folding rule. |
| Failure ergonomics | A case/whitespace typo fails **closed** but presents as "missing required role R" — mitigated by enumerating the present `(fpr, role)` pairs in the error, making the mismatch self-evident. | Forgiving of case/whitespace typos — they just match. |
| Footgun surface | None added; comparison is `==`. | Unicode case-folding has locale traps (e.g. dotless-i); ASCII-only folding is safer but is itself a documented rule the operator must internalize. The fold becomes trusted, must-be-correct code. |
| Operator burden | Use one spelling consistently (documented convention). | May spell loosely; tooling hides drift. |

**Recommendation: A — exact match, no canonicalization in the comparison.** For
compliance-grade SoD, auditability outranks typo-forgiveness, and the failure is
fail-closed (safe) and made self-diagnosing by a good error. Specifics:

- **Comparison-time only, and there is nothing to normalize:** compare
  `VerifiedApprover.Role` **verbatim** against the (validated) config/roster strings
  with `==`. **Never** normalize at verify-time — the role is in the signed preimage,
  so any transform there would break the signature.
- **Config hygiene, not comparison canonicalization:** the loader (§7.4) **rejects**
  empty/whitespace-only and duplicate role strings on the *operator-authored* side
  (loud fail) so config can't carry an invisible trailing-space that would never match.
  It **validates**, it does **not rewrite** — the comparison stays a pure `==`, and the
  signed string is never altered.
- **Self-diagnosing errors:** the missing-role failure (§7.2 step 3) enumerates the
  verified `(fpr, role)` pairs actually present, so a `"QA"`-vs-`"qa"` mismatch is
  obvious at a glance.
- **Canonical form = the literal string, no normalization.** Publish an *unenforced*
  operator convention (lowercase-hyphenated: `qa`, `technical`, `system-owner`) as
  guidance.
- If you instead choose **B**: fold to a copy *only for comparison* (never re-sign,
  never persist the folded form), apply the **same** ASCII trim+lowercase uniformly to
  all three sets at compare time, and document the rule prominently in
  `KNOWN_LIMITATIONS`. (Not recommended.)

### 7.6 go.mod honesty fix (two hops — R4)

`ciphersigil/go.mod:7` still pins `github.com/salehkreiner/netherchat v1.8.0` — a
version that predates **even** `VerifiedArtifactApprovers` / `ArtifactApprovers` /
`ArtifactMeta.ProposalID` (all already used by `internal/record/artifact.go`), and of
course the role API. Only `replace => ../netherchat` (line 14) makes it build.

- **Bump `require` to `v1.10.0`** — the first tag that actually contains the consumed
  role surface (`ArtifactApproverRoles`, `VerifiedApprover`,
  `VerifiedArtifactApproverRoles`). Any claim below v1.10.0 is false against Pass C's
  imports; v1.8.0 is false even against the *pre*-Pass-C imports.
- **Recommendation: keep `replace => ../netherchat` for development.** It builds
  offline against the working tree (currently `v1.10.0` = `059b3f1`); for a
  path-replace, `go.sum` needs no upstream module hash. Bumping `require` to the version
  whose code the replace points at makes the pin *honest* while preserving local
  co-dev. **Alternative** (drop the `replace`, require the real public tag): reproducible
  builds against the immutable tag, but needs network fetch + `go.sum` hashes and loses
  local co-dev — defer to whenever the spine is declared stable (the replace comment at
  `go.mod:11-13` already anticipates this).
- This bump **is part of Pass C** (the read confirmed the plan's earlier "bump to
  v1.9.0 with that tag" step was **never done** — the pin is still v1.8.0).

### 7.7 Invariant preservation & test plan

**Existing count-mode tests that MUST stay green (all `internal/record/artifact_test.go`,
all mutation-style):** `TestArtifactRecordTwoPerson_Genuine` (112),
`TestArtifactRecordTwoPerson_ApproverNotInRoster` (141, the roster-intersection pin),
`TestArtifactRecord_TamperedFailsClosed` (173),
`TestArtifactRecordTwoPerson_AllProposalsMustPass` (221),
`TestArtifactRecord_ForgedAttributionNotTwoPerson` (249),
`TestArtifactRecord_OwnDeliverableIsNoArtifactApprovals` (280). They get only the
mechanical `RosterMember{Name:…}` wrap (§7.3); values, assertions, and count-mode
behavior are unchanged. If the §7.2 shared-core refactor is taken, these six are the
behavior-preservation safety net.

**Existing config tests:** `TestLoadRosterValid/MissingFileIsEmpty/RejectsDuplicate
Fingerprint/RejectsDuplicateName/RejectsMissingFields` (`roster_test.go`) stay green
**unchanged** (R5 — they use `loadRoster` + `Name`, both preserved; `roles` is
`omitempty` and absent from their fixtures). Config test work is **additive**.

**Roster-intersection generalization (the load-bearing rule):** count-mode's
`verified ∩ roster` (`recognizedApprovers`, `artifact.go:150-158`) generalizes to
role-mode's per-role `verified-as-R ∩ roster-authorizes-R` (`F_R`, §7.2 step 3). The
role-mode analog of the line-141 mutation test is mandatory (below).

**New role-mode tests** (`artifact_test.go`; mutation-style where noted):
- **Happy path:** required `{qa, technical}`, two distinct rostered+authorized signers
  each signing their role → passes; `VerifiedArtifactApproverRoles` surfaces both pairs.
- **Missing required role → fail closed:** required `{qa, technical, system-owner}`,
  only `qa`+`technical` present → fails naming the unmet `(proposal, role)`.
- **Role-signed-but-not-rostered → fail closed** (mutation pin for `HasRole`): a valid
  signature as `qa` from a fpr the roster does **not** authorize for `qa` → does not
  count. Reverting the `HasRole` filter makes this pass.
- **Authorized-for-a-different-role → fail closed** (pins per-`(fpr,role)`, not
  per-fpr): fpr authorized for `technical` signs as `qa` → the `qa` requirement is
  unmet by them.
- **Distinct-per-role default** (two tests, pin the toggle): one person authorized for
  both `qa` and `technical` signs **both** → with `AllowSharedPerson=false` (default)
  **fails**; with `true` **passes**. Include the **matching-not-greedy** case
  (`F_qa={Alice,Bob}`, `F_technical={Alice}`, default) → must **pass** (a distinct
  assignment exists), proving the SDR/matching logic (§7.2 step 4).
- **Multi-proposal all-or-nothing:** one proposal meets quorum, sibling doesn't → fails
  naming the sibling.
- **v1/v2 coexistence in one proposal:** a roleless v1 approver + role-typed v2
  approvers → role-mode reads only the v2 subset (count-mode still reads the union);
  quorum evaluated correctly over the v2 pairs.
- **Empty `RequiredRoles` guard:** `ArtifactRecordMeetsRoleQuorum` with no required
  roles → error (no degenerate pass), mirroring count-mode's `n<1`.
- **Fail-closed parity:** tampered / `!Valid` record → error; valid-record-no-proposals
  → `ErrNoArtifactApprovals`.

**New config tests** (`config` package): roles parsed into `RosterMember`; `HasRole`
true/false (incl. not-listed ⇒ false); empty/whitespace role rejected; duplicate role
within one approver rejected; `artifact_quorum.default` → `RoleQuorum`; absent
`artifact_quorum` → `ErrNoRoleQuorum`; malformed (empty `required_roles`) → loud fail;
`allow_shared_person` parsed.

**Fixtures go through the REAL v2 path** (as count-mode fixtures use the real
`AddArtifactApproval`). **Confirmed signatures** (`tui/record/sealer.go`, re-read for
this spec):
`func (s *Sealer) ArtifactApprovalSigningBytesV2(proposalID, role string, pub ed25519.PublicKey) ([]byte, error)`
(line 205) and
`func (s *Sealer) AddArtifactApprovalV2(proposalID, role string, pub ed25519.PublicKey, sig []byte) (string, error)`
(line 230); the matching preimage helper
`protocol.ArtifactApprovalSigningBytesV2(proposalID, artifactHash, approverFpr, nonce, role)`
(line 54). The existing `buildArtifactRecord` helper (`artifact_test.go:71`) gains a
role-bearing approver variant that signs
`protocol.ArtifactApprovalSigningBytesV2(...)` and records via `AddArtifactApprovalV2`.
*Build-time precondition: re-confirm these three signatures unchanged at the moment of
writing fixtures (they are correct as of `059b3f1` / v1.10.0).*

### 7.8 Seam & order of operations (CipherSigil-internal — no tag act)

```
1. Enrich Roster (seal.go) + config (config.go: approverEntry.roles, quorumConfig,
   loaders).            → count-mode tests get the mechanical RosterMember wrap; count-
                          mode BEHAVIOR unchanged.
2. Add the role primitive (artifact.go): RoleQuorum, ArtifactRecordMeetsRoleQuorum,
   eachArtifactProposal core [+ behavior-preserving count-mode delegation].
3. Bump go.mod require v1.8.0 → v1.10.0 (keep replace).
4. Run the suite: count-mode green UNCHANGED; new role-mode + config tests green;
   gofmt; go vet ./...; go build ./...   (Per memory: run `go test` via PowerShell,
   one package at a time — the Bash tool hangs go test on Windows.)
5. NO tag / NO release. CipherSigil is local-only (branch master, no remote), so there
   is no publish act here — distinct from the Netherchat passes (which tag v1.9.0 /
   v1.10.0). go.mod honesty is achieved by the require bump alone.
```

The seam holds because count-mode's public contract and error wording are preserved
and the new primitive is purely additive and unmounted.

### 7.9 What Pass C is NOT doing (anti-bloat)

- **No `app.go` / composition-root edits; no Engine mounting** — enforcement lands
  unmounted (R2).
- **No action-class / risk-tier policy table** — single `requiredRoles`; config merely
  *shaped* to grow one additively (R1).
- **No M3 changes** — `Decide`/`Seal`/`validateSealPolicy` untouched; `roster.Name`
  preserved keeps them compiling.
- **No `ErrDuplicateApprover` activation** — still the deferred N-of-M guard.
- **No Netherchat edits, no new library role logic, no role policy in records.**
- **No removal of the `replace` directive** during development; **no tag** (no remote).

### 7.10 Future pass (deferred — named, not planned here)

**Pass D — App-wiring & action-class enforcement (FUTURE).** What it would entail (one
line, for context only): mount role-typed (and count) artifact verification into the
running app — construct the role-aware `Roster` and quorum policy from config in
`app.go`/`startLocalAPI`, resolve a per-action-class `RoleQuorum` (grow
`quorumConfig.classes` + a class selector binding a record/action to a class), wire the
workflow `Engine` and surface verdicts through the API/UI, and add the identity/sole-
control hardening (KNOWN_LIMITATIONS §3/§5). **Out of scope for Pass C; no part of it is
planned now.**

**What Pass C is NOT (summary):** no Netherchat edits; no change to M3's deliverable
workflow; no role policy in records; no app wiring.

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
