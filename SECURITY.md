# Security Policy

Netherchat is a cryptographic project — Ed25519, SHA-256 hash chains, X25519,
XChaCha20-Poly1305, HKDF. Cryptographic review is actively welcome.

## Supported versions

Only the latest release gets security fixes — **v1.12.0** today. There is no
support branch and no backporting to older tags; if you are running something
older, the fix is to upgrade.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.**

- **Preferred:** GitHub private vulnerability reporting — the **Security** tab of
  this repository has a *Report a vulnerability* button.
- **Alternative:** contact [Astralis Software Systems](https://astralis-systems.com).

A useful report says what you attacked and what happened instead. A proof of
concept, a failing test, or the bytes of a forged record beat prose.

## What to expect

- Acknowledgement within **5 business days**.
- Initial assessment within **14 days** — whether it reproduces, and a severity.
- Coordinated disclosure, with credit unless you would rather stay anonymous.

Netherchat is a one-person project: those are honest targets, not an SLA, and a
complex report may take longer to work through than to acknowledge. There is no
bug bounty — nothing is paid for a report.

## Scope — what is worth your time

- **The sealed-record chain**, construction and offline verification
  (`tui/record`, `sealedrecord`). Can a chain be forged, reordered, truncated, or
  made to verify against a record it does not cover?
- **Artifact approval** — the signed preimage and fingerprint binding in
  `protocol/artifact_signing.go`. Can an approval be replayed onto a different
  proposal, or the artifact swapped under a still-valid signature?
- **Approver-set derivation**, including proposer exclusion. The proposer must
  never count toward its own quorum.
- **The client/server crypto boundary**, enforced at the build-graph level by
  `TestServerBinaryDoesNotLinkClientCrypto`. A path that links the client crypto
  package into the server binary is a finding by itself.
- **The relay's blind-routing claims** — anything that lets the relay learn or
  influence content it should not.

## Out of scope

- Findings that require an already-compromised endpoint. If the attacker has the
  device, they have the keys.
- Denial of service against a self-hosted relay you control.
- Missing hardening headers on the local API.
- Anything under `docs/plans/` — that describes historical work, not shipped
  behavior.

## What we do not claim

[docs/encryption.md](docs/encryption.md) documents the design's limits honestly,
including what is not end-to-end encrypted. A documented limit is not a
vulnerability — but an argument that a limit is worse than documented is.
