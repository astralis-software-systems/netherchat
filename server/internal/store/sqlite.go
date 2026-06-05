package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/salehkreiner/netherchat/protocol"
	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo, keeps static builds)
)

// SQLite is a local, durable Store backed by a pure-Go SQLite database. It keeps
// the static-binary / CGO_ENABLED=0 property (ARCHITECTURE_DECISION.md §1).
type SQLite struct {
	db  *sql.DB
	max int
}

// OpenSQLite opens (creating if needed) a SQLite database at path, retaining up
// to max envelopes per room.
func OpenSQLite(path string, max int) (*SQLite, error) {
	if max <= 0 {
		max = 100
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
	return &SQLite{db: db, max: max}, nil
}

func (s *SQLite) Append(room string, env protocol.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`INSERT INTO messages(room, data) VALUES(?, ?)`, room, data); err != nil {
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
		var data []byte
		if err := rows.Scan(&data); err != nil {
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
