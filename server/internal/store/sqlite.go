package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/salehkreiner/netherchat/protocol"
	"golang.org/x/crypto/hkdf"
	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo, keeps static builds)
)

// sqliteKDFInfo is the HKDF context string that binds the derived at-rest key to
// this specific use (§7). It matches the construction documented in
// docs/encryption.md: key = HKDF-SHA256(secret, "netherchat/sqlite/v1").
const sqliteKDFInfo = "netherchat/sqlite/v1"

// SQLite is a local, durable Store backed by a pure-Go SQLite database. It keeps
// the static-binary / CGO_ENABLED=0 property (ARCHITECTURE_DECISION.md §1).
//
// Each row's payload is additionally encrypted AT REST with AES-256-GCM under a
// key derived from a server-side secret via HKDF-SHA256 (§7). The relay already
// stores only E2E ciphertext (it holds no room key), so this protects the
// remaining plaintext — routing metadata and message shape — from a stolen disk.
// AES-GCM is stdlib (crypto/aes, crypto/cipher), so encryption costs us no cgo.
type SQLite struct {
	db   *sql.DB
	max  int
	aead cipher.AEAD
}

// OpenSQLite opens (creating if needed) an encrypted SQLite database at path,
// retaining up to max envelopes per room. secret is the at-rest root secret
// (see server.persistSecret): the AES-256 key is HKDF-derived from it, never
// stored, so the database is unreadable without it. secret must be non-empty.
func OpenSQLite(path string, max int, secret []byte) (*SQLite, error) {
	if max <= 0 {
		max = 100
	}
	aead, err := newAtRestAEAD(secret)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS messages (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			room TEXT NOT NULL,
			data BLOB NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room, id);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &SQLite{db: db, max: max, aead: aead}, nil
}

// newAtRestAEAD derives the AES-256-GCM AEAD from secret via HKDF-SHA256 with the
// fixed sqliteKDFInfo context.
func newAtRestAEAD(secret []byte) (cipher.AEAD, error) {
	if len(secret) == 0 {
		return nil, errors.New("sqlite persistence requires a non-empty at-rest encryption secret")
	}
	r := hkdf.New(sha256.New, secret, nil, []byte(sqliteKDFInfo))
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive sqlite key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init aes: %w", err)
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext, returning nonce || ciphertext (the on-disk blob).
func (s *SQLite) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	// Seal appends the ciphertext to the nonce prefix, so the blob is self-framing.
	return s.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// open reverses seal.
func (s *SQLite) open(blob []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("stored row is too short to be a sealed payload")
	}
	pt, err := s.aead.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt row (wrong key or tampered db): %w", err)
	}
	return pt, nil
}

func (s *SQLite) Append(room string, env protocol.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	enc, err := s.seal(data)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO messages(room, data) VALUES(?, ?)`, room, enc); err != nil {
		return err
	}
	// Trim to the most-recent max per room.
	_, err = s.db.Exec(`
		DELETE FROM messages
		WHERE room = ? AND id NOT IN (
			SELECT id FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?
		)`, room, room, s.max)
	return err
}

func (s *SQLite) History(room string, limit int) ([]protocol.Envelope, error) {
	if limit <= 0 || limit > s.max {
		limit = s.max
	}
	// Newest first, then reverse so the caller gets oldest-first.
	rows, err := s.db.Query(`SELECT data FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?`, room, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rev []protocol.Envelope
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, err
		}
		data, err := s.open(blob)
		if err != nil {
			return nil, err
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, err
		}
		rev = append(rev, env)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]protocol.Envelope, len(rev))
	for i, e := range rev {
		out[len(rev)-1-i] = e
	}
	return out, nil
}

func (s *SQLite) Close() error { return s.db.Close() }
