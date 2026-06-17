# The Sealed-Record library

Netherchat's sealed record — Ed25519-signed, SHA-256 hash-chained, append-only,
offline-verifiable — is available as a standalone, importable Go library. Any
external program can **create and verify** sealed records, render reports, and
verify rosters/receipts with **no running relay and no network**.

```go
import "github.com/salehkreiner/netherchat/sealedrecord"
```

`sealedrecord` is a thin façade over the implementation packages under `tui/`
(`record`, `report`, `attest`). Those packages live under `tui/` deliberately: it
is the only subtree Go's `internal/` rule lets import Netherchat's internal crypto
helpers, which is what keeps "the blind relay cannot read message content" a
property of the build graph. The façade re-exports their full public surface at a
stable, relay-free import path, so external consumers never reach into any
`internal/` package. (A guard test fails the build if the façade ever drifts out
of sync with the implementation packages.)

The relay binary still does **not** link the crypto package — verified by
`TestServerBinaryDoesNotLinkClientCrypto` — and none of this changes that.

## Quick start: produce and verify, with no relay

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/salehkreiner/netherchat/sealedrecord"
)

func main() {
	// An identity is just an Ed25519 keypair; its AuthorID is the key fingerprint.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	author := sealedrecord.Author{
		ID:   sealedrecord.Fingerprint(pub),
		Name: "alice",
		Key:  pub,
		Sign: func(b []byte) ([]byte, error) { return ed25519.Sign(priv, b), nil },
	}

	// Build an append-only chain of signed entries.
	chain := sealedrecord.NewChain()
	chain.AppendNew(author, sealedrecord.KindDecision, "", "rolled back to v2.3.1")

	// Seal it: collect co-signatures over the chain head, then finalize.
	sealer := sealedrecord.NewSealer("ops", author.ID, chain.Entries())
	sealer.Sign(author)                  // bare co-signature
	rec, _ := sealer.Finalize()

	// Marshal to disk, then verify the bytes from scratch.
	b, _ := rec.Marshal()
	res, _ := sealedrecord.VerifyBytes(b) // VALID / TAMPERED + specific Reason
	fmt.Println(res.Valid, res.Entries, len(res.Signers))

	// Render a self-contained HTML report (executive mode hides hashes/fprs).
	_ = sealedrecord.RenderHTML(rec, res, sealedrecord.Options{})
}
```

### Core API

| Purpose | Symbol |
|---|---|
| Build an entry chain | `NewChain`, `(*Chain).AppendNew`, `(*Chain).Append` |
| Compute an identity fingerprint | `Fingerprint(ed25519.PublicKey) string` |
| Seal (collect co-signatures, offline) | `NewSealer`, `(*Sealer).Sign`/`SignAs`/`AddCosignature`/`AddEndorsement`/`Finalize` |
| Verify | `Verify(*SealedRecord)`, `VerifyBytes([]byte)` → `*VerifyResult{Valid, Reason, …}` |
| Render | `RenderHTML`, `RenderMarkdown`, `RenderMinutes`, `Options` |
| Roster / receipt | `NewRoster`, `VerifyRoster`, `ParseReceipt`, `VerifyReceipt`, … |

`Verify` returns `Valid=true` (VALID) or `Valid=false` with a specific `Reason`
(TAMPERED — e.g. *"entry 2 prev_hash does not link to the previous entry"*). `err`
is non-nil only for input too malformed to parse.

## Backward compatibility & versioning

Every record produced before these features keeps verifying **VALID, unchanged**.
The on-disk schema is versioned: a record, entry, or seal signature uses its **v1**
layout unless it carries a v2 field, in which case it uses a distinct,
domain-separated **v2** layout. The choice is a pure function of content, so any
tampering that adds or removes a v2 field flips the layout and breaks the
signature. `Verify` accepts both `v1` and `v2`; the wire byte layouts are pinned in
[`PROTOCOL.md`](../PROTOCOL.md) §16.

## Electronic-signature meanings

A seal co-signature (or a two-person-rule approval) can declare a machine-readable
**meaning**, the signer's printed **name**, and a UTC **timestamp** — all part of
the signed payload, so none can be altered without breaking verification.

Four meanings ship as defaults; the set is **extensible** — `Meaning` is an opaque,
signed string, so a consumer may declare its own:

```go
sealedrecord.MeaningAuthored
sealedrecord.MeaningReviewed
sealedrecord.MeaningApproved
sealedrecord.MeaningRejected
```

Seal with a declared meaning:

```go
sealer := sealedrecord.NewSealer("ops", author.ID, chain.Entries())
sealer.SignAs(author, sealedrecord.MeaningApproved)            // records name + UTC time
// collect a remote co-signature carrying a meaning:
sealer.AddEndorsement(reviewerPub, sig, sealedrecord.MeaningReviewed, "Dr. Bob", "2026-06-17T09:30:00Z")
rec, _ := sealer.Finalize()
```

The finalized record exposes them as `rec.Endorsements[fpr] = {Meaning, Name,
SignedAt}`. In the running client, `/seal approved` declares the meaning over the
wire, and a two-person-rule `/approve` carries the `approved` meaning by default
(use `ApproveActionAs` for another). The report shows, for each signer, **who**
signed, **with what meaning**, and **when** — in both full and executive modes
(executive still hides hashes/fingerprints).

## Typed record kinds

Beyond the built-in `decision` / `action` / `note` / `artifact`, an entry can carry
a **consumer-defined typed kind**: `KindTyped` plus an opaque `Schema` tag and an
optional `SchemaVer`. The library never interprets the tag — your application
supplies the meaning. The tag is part of the signed bytes.

```go
chain.Append(author, sealedrecord.EntrySpec{
	Kind:      sealedrecord.KindTyped,
	Schema:    "transcript",   // opaque to the library
	SchemaVer: "1",
	Body:      "sha256:…",
})
```

## Cross-record traceability links

An entry can reference one or more prior records by hash, forming a
cryptographically verifiable lineage (e.g. *transcript → derived document → further
document*). A link is generic — just a hash and a relationship label, with **no**
domain semantics — and is part of the signed payload.

```go
chain.Append(author, sealedrecord.EntrySpec{
	Kind: sealedrecord.KindDecision,
	Body: "ratified the parent findings",
	Links: []sealedrecord.Link{
		{Hash: parent.HeadHash, Relation: "derived-from"},
	},
})
```

To validate lineage, verify the child record and confirm a link's `Hash` matches a
supplied parent's `HeadHash` (and verify the parent independently).

## Durable "case room" profile (opt-in persistence)

By default a relay keeps **nothing** — ephemeral, zero-persistence — and that
remains the documented norm. A room can **opt in** to durable persistence for the
life of a review cycle using the existing encrypted-SQLite store, so its history
survives the room going empty and the server restarting:

```toml
[persistence]
path = "/var/lib/netherchat/case.db"   # encrypted at rest (AES-256-GCM via HKDF)
# enabled = false                       # global persistence stays OFF (the default)

[rooms.case-001]
durable = true                          # this room persists; others keep nothing
```

Persisted rows are **ciphertext encrypted at rest** exactly as the global SQLite
option — the relay still holds no room key and cannot read them. With global
`enabled = false`, only rooms marked `durable = true` are persisted; every other
room keeps nothing. Set `[persistence].path` so the at-rest store is the encrypted
SQLite database (an in-memory fallback is not durable across restarts). See
[`docs/encryption.md`](encryption.md) for the at-rest key handling.
