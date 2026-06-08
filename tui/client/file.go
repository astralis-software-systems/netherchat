package client

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/salehkreiner/netherchat/protocol"
	"github.com/salehkreiner/netherchat/tui/internal/crypto"
)

// This file is the client half of the ephemeral artifact relay (§2.3): a secure
// transfer courier, NOT file sharing. The sender streams an artifact as E2E
// ciphertext the relay forwards and forgets; the receiver buffers chunks in
// memory, verifies the whole-artifact SHA-256, and writes it out atomically.
// Nothing is stored on the relay; when the room scuttles the transfer is gone.

const (
	fileWindow     = 64               // chunks the sender keeps in flight before waiting on an ack
	fileAckEvery   = 16               // receiver acks every N chunks (and on completion)
	fileStall      = 30 * time.Second // give up if the window is full this long with no ack
	fileFlushGrace = 3 * time.Second  // after the last chunk, wait this long for a final ack / abort
)

// sendState is our outgoing transfer's coordination with the read loop: incoming
// FileAcks pace the stream; a FileAbort cancels it.
type sendState struct {
	filename string
	acks     chan int
	aborts   chan string
}

// recvState is an incoming transfer being reassembled in memory. Its fields are
// touched only by the single read-loop goroutine, so they need no lock; the maps
// that hold it are guarded by Client.fileMu.
type recvState struct {
	meta       protocol.FileOfferMeta
	cleanName  string
	senderID   string
	senderName string
	rk         crypto.RoomKey // snapshot at offer time; chunks decrypt under this epoch
	chunks     [][]byte
	have       []bool
	received   int
	bytes      int64
}

// SetMaxFileBytes overrides the per-artifact size cap (default
// protocol.DefaultMaxFileBytes). The relay cannot enforce size (it is sealed), so
// this client-side cap is what bounds both an outgoing offer and an incoming
// buffer. Call before any transfer.
func (c *Client) SetMaxFileBytes(n int64) {
	if n > 0 {
		c.maxFileBytes = n
	}
}

// MaxFileBytes reports the current per-artifact size cap.
func (c *Client) MaxFileBytes() int64 { return c.maxFileBytes }

// SendFile streams a local artifact to the room as an end-to-end-encrypted,
// relay-blind transfer (§2.3). It validates synchronously — returning an error for
// an unreadable file, one over the size cap (rejected at offer time), or a room
// with no key yet — then streams asynchronously, reporting via events
// (EvFileProgress, then EvFileSent or EvFileFailed). The relay never sees the
// artifact.
func (c *Client) SendFile(path string) error {
	c.mu.Lock()
	rk := c.rk
	selfID := c.selfID
	c.mu.Unlock()
	if rk == nil {
		return errors.New("room key not established yet")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read artifact: %w", err)
	}
	if int64(len(data)) > c.maxFileBytes {
		return fmt.Errorf("artifact is %s; transfers are capped at %s (rejected at offer time)",
			humanBytes(int64(len(data))), humanBytes(c.maxFileBytes))
	}

	filename := filepath.Base(path)
	sum := sha256.Sum256(data)
	chunks := (len(data) + protocol.ChunkSize - 1) / protocol.ChunkSize
	if chunks == 0 {
		chunks = 1 // a zero-byte artifact is one empty chunk
	}
	tid := newTransferID()

	// Seal the offer metadata exactly like a message (signed); the receiver
	// verifies the signature before accepting a single chunk.
	meta := protocol.FileOfferMeta{
		TransferID: tid, Filename: filename, Size: int64(len(data)),
		Chunks: chunks, SHA256: hex.EncodeToString(sum[:]),
	}
	metaJSON, _ := json.Marshal(meta)
	nonce, ct, sig, err := c.id.SealMessage(*rk, c.room, selfID, metaJSON)
	if err != nil {
		return fmt.Errorf("seal offer: %w", err)
	}
	c.enqueue(protocol.OpFileOffer, protocol.FileOffer{
		TransferID: tid,
		Sealed:     protocol.Message{FromID: selfID, Epoch: rk.Epoch, Nonce: nonce, Ciphertext: ct, Sig: sig},
	})

	ss := &sendState{filename: filename, acks: make(chan int, 128), aborts: make(chan string, 1)}
	c.fileMu.Lock()
	c.sends[tid] = ss
	c.fileMu.Unlock()

	go c.streamChunks(tid, filename, data, chunks, *rk, ss)
	return nil
}

// streamChunks encrypts and emits the artifact's chunks, paced by FileAcks so it
// never overruns a receiver, and reports the outcome as an event.
func (c *Client) streamChunks(tid, filename string, data []byte, total int, rk crypto.RoomKey, ss *sendState) {
	defer func() {
		c.fileMu.Lock()
		delete(c.sends, tid)
		c.fileMu.Unlock()
	}()

	start := time.Now()
	totalBytes := int64(len(data))
	maxAck := 0
	lastPct := -1

	broadcastFail := func(reason string) {
		c.sendFileAbort(tid, reason) // tell receivers to discard
		c.emit(EvFileFailed{Filename: filename, TransferID: tid, Reason: reason})
	}
	quietFail := func(reason string) { // the abort came FROM a receiver; don't echo it back
		c.emit(EvFileFailed{Filename: filename, TransferID: tid, Reason: reason})
	}

	for i := 0; i < total; i++ {
		// Flow control: stay within a window of the slowest acknowledgement.
		for i-maxAck >= fileWindow {
			select {
			case k := <-ss.acks:
				if k > maxAck {
					maxAck = k
				}
			case reason := <-ss.aborts:
				quietFail("aborted by receiver: " + reason)
				return
			case <-time.After(fileStall):
				broadcastFail("transfer stalled — no acknowledgement from the receiver")
				return
			case <-c.ctx.Done():
				return
			}
		}

		lo := i * protocol.ChunkSize
		hi := lo + protocol.ChunkSize
		if hi > len(data) {
			hi = len(data)
		}
		nonce, ctData, err := crypto.SealChunk(rk, data[lo:hi])
		if err != nil {
			broadcastFail("encrypt chunk: " + err.Error())
			return
		}
		c.enqueue(protocol.OpFileChunk, protocol.FileChunk{
			TransferID: tid, Index: i, Total: total, Nonce: nonce, Data: ctData,
		})

		if pct := percent(i+1, total); pct != lastPct || i == total-1 {
			lastPct = pct
			c.emit(EvFileProgress{
				Filename: filename, TransferID: tid, SentChunks: i + 1, TotalChunks: total,
				SentBytes: int64(hi), TotalBytes: totalBytes,
			})
		}

		// Absorb any pending acks/aborts without blocking.
		select {
		case k := <-ss.acks:
			if k > maxAck {
				maxAck = k
			}
		case reason := <-ss.aborts:
			quietFail("aborted by receiver: " + reason)
			return
		default:
		}
	}

	// All chunks streamed. Wait briefly for a final ack or an abort (a receiver
	// SHA-256 mismatch arrives as an abort) before declaring success.
	deadline := time.After(fileFlushGrace)
	for maxAck < total {
		select {
		case k := <-ss.acks:
			if k > maxAck {
				maxAck = k
			}
		case reason := <-ss.aborts:
			quietFail("aborted by receiver: " + reason)
			return
		case <-deadline:
			maxAck = total // delivered as far as we can tell; receiver may still be finalizing
		case <-c.ctx.Done():
			return
		}
	}
	c.emit(EvFileSent{Filename: filename, TransferID: tid, Size: totalBytes, Elapsed: time.Since(start)})
}

// --- receive ----------------------------------------------------------------

// onFileOffer verifies an incoming transfer offer and begins buffering. The offer
// signature is checked BEFORE any chunk is accepted; the filename is re-sanitized
// even though the sender sanitized it.
func (c *Client) onFileOffer(fo protocol.FileOffer) {
	c.mu.Lock()
	rk := c.rk
	sender, known := c.members[fo.Sealed.FromID]
	c.mu.Unlock()
	if rk == nil || !known {
		return // an offer before our key, or from an unknown member — ignore
	}

	pt, signed, err := crypto.OpenMessage(*rk, sender.signPub, c.room, fo.Sealed.FromID,
		fo.Sealed.Epoch, fo.Sealed.Nonce, fo.Sealed.Ciphertext, fo.Sealed.Sig)
	if err != nil {
		c.emit(EvError{Err: fmt.Errorf("artifact offer from @%s failed verification", sender.name)})
		return
	}
	if !signed {
		c.emit(EvError{Err: fmt.Errorf("rejecting an unsigned artifact offer from @%s", sender.name)})
		return
	}
	var meta protocol.FileOfferMeta
	if json.Unmarshal(pt, &meta) != nil || meta.TransferID != fo.TransferID {
		c.emit(EvError{Err: errors.New("malformed artifact offer")})
		return
	}
	if meta.Size > c.maxFileBytes {
		c.sendFileAbort(fo.TransferID, "exceeds the size cap")
		c.emitRecvFailed(sender.name, meta.Filename, meta.Size, fo.TransferID, "artifact exceeds the size cap")
		return
	}
	clean, changed, serr := sanitizeFilename(meta.Filename)
	if serr != nil {
		c.sendFileAbort(fo.TransferID, "unsafe filename")
		c.emitRecvFailed(sender.name, meta.Filename, meta.Size, fo.TransferID, "unsafe filename: "+serr.Error())
		return
	}
	if changed {
		// Security warning: the sender's name resolved to something else once
		// stripped of directory components.
		c.emit(EvError{Err: fmt.Errorf("sanitized incoming artifact name %q → %q", meta.Filename, clean)})
	}

	rs := &recvState{
		meta: meta, cleanName: clean, senderID: fo.Sealed.FromID, senderName: sender.name,
		rk: *rk, chunks: make([][]byte, meta.Chunks), have: make([]bool, meta.Chunks),
	}
	c.fileMu.Lock()
	c.recvs[fo.TransferID] = rs
	c.fileMu.Unlock()
	c.emit(EvFileOffer{
		From: sender.name, Fpr: crypto.Fingerprint(sender.signPub),
		Filename: clean, Size: meta.Size, TransferID: fo.TransferID, At: time.Now(),
	})
}

// onFileChunk decrypts and stores one chunk, acking progress and finalizing once
// the artifact is complete.
func (c *Client) onFileChunk(fc protocol.FileChunk) {
	c.fileMu.Lock()
	rs := c.recvs[fc.TransferID]
	c.fileMu.Unlock()
	if rs == nil || fc.Index < 0 || fc.Index >= len(rs.chunks) {
		return // not for us (we may be the sender), or out of range
	}

	pt, err := crypto.OpenChunk(rs.rk, fc.Nonce, fc.Data)
	if err != nil {
		c.abortRecv(fc.TransferID, "chunk decryption failed")
		return
	}
	if !rs.have[fc.Index] {
		rs.chunks[fc.Index] = pt
		rs.have[fc.Index] = true
		rs.received++
		rs.bytes += int64(len(pt))
	}
	if rs.bytes > c.maxFileBytes {
		c.abortRecv(fc.TransferID, "transfer exceeds the size cap")
		return
	}
	if rs.received%fileAckEvery == 0 || rs.received == len(rs.chunks) {
		c.enqueue(protocol.OpFileAck, protocol.FileAck{TransferID: fc.TransferID, Received: rs.received})
	}
	if rs.received == len(rs.chunks) {
		c.finalizeRecv(fc.TransferID)
	}
}

// finalizeRecv verifies the reassembled artifact and writes it out, or aborts on a
// SHA-256 mismatch.
func (c *Client) finalizeRecv(tid string) {
	c.fileMu.Lock()
	rs := c.recvs[tid]
	delete(c.recvs, tid)
	c.fileMu.Unlock()
	if rs == nil {
		return
	}

	var buf []byte
	for _, ch := range rs.chunks {
		buf = append(buf, ch...)
	}
	sum := sha256.Sum256(buf)
	if hex.EncodeToString(sum[:]) != rs.meta.SHA256 {
		// Never write a corrupt artifact: we verify in memory, so there is no temp
		// file to leave behind. Tell the sender so it reports the failure too.
		c.sendFileAbort(tid, "sha256 mismatch")
		c.emitRecvFailed(rs.senderName, rs.cleanName, rs.meta.Size, tid, "integrity check failed (sha256 mismatch)")
		return
	}
	dst, err := writeArtifact(rs.cleanName, buf)
	if err != nil {
		c.emitRecvFailed(rs.senderName, rs.cleanName, rs.meta.Size, tid, "write failed: "+err.Error())
		return
	}
	c.emit(EvFileComplete{
		From: rs.senderName, Filename: filepath.Base(dst), Path: dst,
		Size: rs.meta.Size, TransferID: tid, OK: true, At: time.Now(),
	})
}

// abortRecv tears down an incoming transfer we cannot complete, telling the sender.
func (c *Client) abortRecv(tid, reason string) {
	c.fileMu.Lock()
	rs := c.recvs[tid]
	delete(c.recvs, tid)
	c.fileMu.Unlock()
	c.sendFileAbort(tid, reason)
	if rs != nil {
		c.emitRecvFailed(rs.senderName, rs.cleanName, rs.meta.Size, tid, reason)
	}
}

// onFileAck routes a receiver's progress to our streaming goroutine (if we are the
// sender of that transfer).
func (c *Client) onFileAck(fa protocol.FileAck) {
	c.fileMu.Lock()
	ss := c.sends[fa.TransferID]
	c.fileMu.Unlock()
	if ss != nil {
		select {
		case ss.acks <- fa.Received:
		default:
		}
	}
}

// onFileAbort handles a teardown for either our outgoing or incoming transfer.
func (c *Client) onFileAbort(fa protocol.FileAbort) {
	c.fileMu.Lock()
	if ss := c.sends[fa.TransferID]; ss != nil {
		c.fileMu.Unlock()
		select {
		case ss.aborts <- fa.Reason:
		default:
		}
		return
	}
	rs := c.recvs[fa.TransferID]
	delete(c.recvs, fa.TransferID)
	c.fileMu.Unlock()
	if rs != nil {
		c.emitRecvFailed(rs.senderName, rs.cleanName, rs.meta.Size, fa.TransferID, "transfer aborted by sender: "+fa.Reason)
	}
}

func (c *Client) sendFileAbort(tid, reason string) {
	c.enqueue(protocol.OpFileAbort, protocol.FileAbort{TransferID: tid, Reason: reason})
}

func (c *Client) emitRecvFailed(from, filename string, size int64, tid, reason string) {
	c.emit(EvFileComplete{
		From: from, Filename: filename, Size: size, TransferID: tid, OK: false, Err: reason, At: time.Now(),
	})
}

// --- file system + naming ---------------------------------------------------

// sanitizeFilename reduces a sender-supplied name to a safe basename in the
// current directory. It strips all directory components (treating both separators
// so a Linux sender's path is neutralised on a Windows receiver and vice-versa)
// and REJECTS names with null bytes, pure traversal, or that resolve to a dotfile
// — a malicious sender must not overwrite the receiver's ~/.ssh or shell rc.
func sanitizeFilename(name string) (clean string, changed bool, err error) {
	clean = path.Base(strings.ReplaceAll(name, "\\", "/"))
	changed = clean != name
	switch {
	case strings.ContainsRune(clean, 0):
		return "", changed, errors.New("filename contains a null byte")
	case clean == "" || clean == "." || clean == "..":
		return "", changed, errors.New("empty or traversal-only filename")
	case strings.HasPrefix(clean, "."):
		return "", changed, errors.New("refusing to auto-write a dotfile")
	}
	return clean, changed, nil
}

// writeArtifact writes data to the current working directory under name (with
// _1/_2 suffixes on collision), atomically and without following symlinks: it
// O_EXCL-creates a randomized temp file, fsyncs, then renames over the final name
// — and rename operates on the link itself, never the symlink target.
func writeArtifact(name string, data []byte) (string, error) {
	final := uniqueFilename(name)
	tmp := fmt.Sprintf("%s.%s.nctmp", final, randHex(6))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := firstErr(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return final, nil
}

// uniqueFilename returns name, or name with an _N suffix, that does not yet exist.
// It uses Lstat so a pre-existing symlink counts as "taken" (never followed).
func uniqueFilename(name string) string {
	if !pathExists(name) {
		return name
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; ; i++ {
		cand := fmt.Sprintf("%s_%d%s", stem, i, ext)
		if !pathExists(cand) {
			return cand
		}
	}
}

func pathExists(p string) bool {
	_, err := os.Lstat(p) // Lstat: do not follow a symlink
	return err == nil
}

// --- small helpers ----------------------------------------------------------

func newTransferID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:]) // 16 hex chars
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func percent(done, total int) int {
	if total <= 0 {
		return 100
	}
	return int(float64(done) / float64(total) * 100)
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// humanBytes renders a byte count like "4.2 MB" for progress and error text.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
