// Group / room crypto — the browser counterpart of tui/internal/crypto/group.go.
// Every operation here is byte-compatible with the Go implementation so a web
// client and a TUI client can share a room transparently.
//
//   - Room key wrap/unwrap : nacl/box  (X25519 + XSalsa20-Poly1305)
//   - Message AEAD         : XChaCha20-Poly1305 (24-byte random nonce, IETF)
//   - Epoch ratchet        : HKDF-SHA256
//
// The AEAD additional data is the 8-byte big-endian epoch, and the message
// signature covers protocol/signing.ts SigningBytes — both identical to Go.

import nacl from "tweetnacl";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "./random";
import { signingBytes, u64be, utf8 } from "./signing";
import type { Identity } from "./identity";

export interface RoomKey {
  epoch: number;
  key: Uint8Array; // 32 bytes
}

// HKDF info string for the forward-secret epoch ratchet. Must match Go's
// "netherchat/epoch-ratchet/v1" exactly.
const RATCHET_INFO = utf8("netherchat/epoch-ratchet/v1");

/** Fresh random room key. Used by the first member (epoch 0) and on member add. */
export function newRoomKey(epoch = 0): RoomKey {
  return { epoch, key: randomBytes(32) };
}

/**
 * Advance the room key by one epoch via HKDF (salt nil -> zero-filled, matching
 * Go's hkdf.New with a nil salt). Deterministic, so every member that applies it
 * lands on the same next key with no key exchange — used for /vanish.
 */
export function ratchet(rk: RoomKey): RoomKey {
  const next = hkdf(sha256, rk.key, undefined, RATCHET_INFO, 32);
  return { epoch: rk.epoch + 1, key: next };
}

/** Seal a room key for a recipient's X25519 public key (nacl/box). */
export function wrapRoomKey(
  id: Identity,
  rk: RoomKey,
  recipientKX: Uint8Array,
): { nonce: Uint8Array; wrapped: Uint8Array } {
  const nonce = randomBytes(24);
  const wrapped = nacl.box(rk.key, nonce, recipientKX, id.kxSecret);
  return { nonce, wrapped };
}

/** Open a wrapped room key, verifying it came from senderKX. */
export function unwrapRoomKey(
  id: Identity,
  epoch: number,
  nonce: Uint8Array,
  wrapped: Uint8Array,
  senderKX: Uint8Array,
): RoomKey {
  if (nonce.length !== 24) throw new Error(`wrap nonce wrong length: ${nonce.length}`);
  const opened = nacl.box.open(wrapped, nonce, senderKX, id.kxSecret);
  if (!opened) throw new Error("room key unwrap failed: box authentication error");
  if (opened.length !== 32) throw new Error(`unwrapped room key wrong length: ${opened.length}`);
  return { epoch, key: opened };
}

export interface SealedMessage {
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  signature: Uint8Array;
}

/**
 * Encrypt plaintext under the room key (XChaCha20-Poly1305, epoch as AAD) and
 * sign the result with the sender's Ed25519 key.
 */
export function sealMessage(
  id: Identity,
  rk: RoomKey,
  fromID: string,
  plaintext: Uint8Array,
): SealedMessage {
  const nonce = randomBytes(24);
  const aead = xchacha20poly1305(rk.key, nonce, u64be(rk.epoch));
  const ciphertext = aead.encrypt(plaintext);
  const signature = nacl.sign.detached(
    signingBytes(fromID, rk.epoch, nonce, ciphertext),
    id.signSecret,
  );
  return { nonce, ciphertext, signature };
}

/**
 * Verify the sender's signature (BEFORE decrypting, so a forged ciphertext never
 * touches the AEAD) and decrypt. Throws on any failure.
 */
export function openMessage(
  rk: RoomKey,
  senderSignPub: Uint8Array,
  fromID: string,
  epoch: number,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  if (senderSignPub.length !== 32) throw new Error("sender signing key invalid");
  if (
    !nacl.sign.detached.verify(
      signingBytes(fromID, epoch, nonce, ciphertext),
      signature,
      senderSignPub,
    )
  ) {
    throw new Error("message signature verification failed");
  }
  if (rk.epoch !== epoch) {
    throw new Error(`epoch mismatch: holding key for epoch ${rk.epoch}, message is epoch ${epoch}`);
  }
  const aead = xchacha20poly1305(rk.key, nonce, u64be(epoch));
  return aead.decrypt(ciphertext);
}
