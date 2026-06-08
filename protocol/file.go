package protocol

// Ephemeral file relay (§2.3): a secure ARTIFACT RELAY, not file sharing. An
// engineer hands an artifact (a credential, a heap dump, a config, a key, a log)
// to someone in the room as ciphertext that transits the relay and lands on the
// recipient's machine — the relay stores not a single byte, and when the room
// scuttles the transfer is gone everywhere. This is a courier, not a bucket.
//
// Wire shape, additive over protocol v3:
//
//   - OpFileOffer carries a content-free transfer id IN CLEARTEXT (so the blind
//     relay can count concurrent transfers) plus a sealed, signed Message holding
//     the only sensitive metadata (filename, size, sha256). The relay never learns
//     what is being transferred.
//   - OpFileChunk carries routing metadata in cleartext (transfer id, chunk index
//     and count — size-class metadata the relay already sees for messages) and the
//     chunk itself as XChaCha20-Poly1305 ciphertext under the room key. The relay
//     forwards and forgets; it cannot reconstruct the artifact.
//   - OpFileAck reports a receiver's progress, pacing the sender.
//   - OpFileAbort tears a transfer down cleanly (mismatch, size cap, cancel,
//     sender disconnect).
const (
	OpFileOffer Op = "file_offer" // sender -> room: announce a transfer (cleartext id + sealed metadata)
	OpFileChunk Op = "file_chunk" // sender -> room: one E2E-encrypted slice of the artifact
	OpFileAck   Op = "file_ack"   // receiver -> room: chunks received so far (progress / flow control)
	OpFileAbort Op = "file_abort" // either side -> room: this transfer is over
)

// File-transfer bounds. The artifact relay is deliberately bounded: small, in
// memory, one artifact at a time — never a storage tier.
const (
	// ChunkSize is the plaintext bytes per chunk (64 KiB).
	ChunkSize = 64 << 10

	// DefaultMaxFileBytes caps a single artifact at 50 MiB. It is a CLIENT policy:
	// a blind relay cannot see a transfer's size (it is sealed), so the sender
	// refuses larger files at offer time and the receiver aborts if its in-memory
	// buffer would exceed it. Operators may tune it via [limits] max_file_bytes.
	DefaultMaxFileBytes int64 = 50 << 20

	// DefaultMaxConcurrentTransfers bounds in-flight transfers per room. Unlike the
	// size cap this IS relay-enforceable, because the relay sees the (content-free)
	// transfer ids.
	DefaultMaxConcurrentTransfers = 3

	// MaxChunkWire bounds the encrypted chunk a relay will forward: the 64 KiB
	// plaintext plus XChaCha20-Poly1305 overhead (the 16-byte tag rides in the
	// ciphertext; the 24-byte nonce travels in its own field) and a little slack.
	// The relay rejects anything larger to bound per-frame memory.
	MaxChunkWire = ChunkSize + 256
)

// FileOffer announces a transfer (§2.3). TransferID is a random, content-free
// routing id the BLIND RELAY uses to count concurrent transfers and to correlate
// chunks; it reveals nothing about the artifact. Every sensitive field lives
// ENCRYPTED + Ed25519-SIGNED in Sealed, so the relay never learns the filename,
// size, or hash — and the receiver verifies Sealed's signature before accepting a
// single chunk.
type FileOffer struct {
	TransferID string  `json:"transfer_id"`
	Sealed     Message `json:"sealed"`
}

// FileOfferMeta is the END-TO-END-ENCRYPTED plaintext inside FileOffer.Sealed.
// TransferID is bound here too so a receiver can confirm the cleartext id was not
// tampered with by a relay.
type FileOfferMeta struct {
	TransferID string `json:"transfer_id"`
	Filename   string `json:"filename"` // basename only; sender sanitizes, receiver re-sanitizes
	Size       int64  `json:"size"`
	Chunks     int    `json:"chunks"`
	SHA256     string `json:"sha256"` // hex SHA-256 of the plaintext artifact, verified on reassembly
}

// FileChunk carries one encrypted slice. TransferID/Index/Total are content-free
// routing metadata (the relay forwards by them and frees the transfer's slot when
// it forwards the final chunk); Nonce/Data are the XChaCha20-Poly1305 nonce and
// ciphertext of the chunk under the room key — opaque to the relay, exactly like a
// message body.
type FileChunk struct {
	TransferID string `json:"transfer_id"`
	Index      int    `json:"index"`
	Total      int    `json:"total"`
	Nonce      []byte `json:"nonce"`
	Data       []byte `json:"data"`
}

// FileAck reports how many chunks a receiver has, which paces the sender and
// drives the receiver-side progress line.
type FileAck struct {
	TransferID string `json:"transfer_id"`
	Received   int    `json:"received"`
}

// FileAbort ends a transfer: a SHA-256 mismatch or size cap on the receiver, a
// cancel, or the sender disconnecting mid-transfer.
type FileAbort struct {
	TransferID string `json:"transfer_id"`
	Reason     string `json:"reason"`
}
