// Status Beacon crypto (browser side, §1.2) — the counterpart of
// tui/internal/crypto/beacon.go. A beacon reader receives the beacon key in the
// link, so it only needs to DECRYPT; deriveBeaconKey is provided for cross-impl
// tests. Both operations are byte-compatible with the Go implementation.
//
//   - beacon key : HKDF-SHA256(room_key, salt=nil, "netherchat/beacon/v1")[:32]
//   - status AEAD: XChaCha20-Poly1305, blob = nonce(24) || ciphertext, no AAD

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

const NONCE = 24;
const BEACON_INFO = new TextEncoder().encode("netherchat/beacon/v1");

/**
 * Derive the beacon key from a room key — distinct from the message key, matching
 * Go's crypto.BeaconKey. (The reader normally gets this value from the link; this
 * exists for interop testing.)
 */
export function deriveBeaconKey(roomKey: Uint8Array): Uint8Array {
  return hkdf(sha256, roomKey, undefined, BEACON_INFO, 32);
}

/**
 * Decrypt a beacon blob (nonce(24) || ciphertext) under the beacon key, matching
 * Go's crypto.SealBeacon/OpenBeacon. Throws on a short blob or a failed AEAD tag.
 */
export function openBeacon(beaconKey: Uint8Array, blob: Uint8Array): string {
  if (beaconKey.length !== 32) throw new Error("beacon key must be 32 bytes");
  if (blob.length < NONCE) throw new Error("beacon blob too short");
  const nonce = blob.subarray(0, NONCE);
  const ct = blob.subarray(NONCE);
  const aead = xchacha20poly1305(beaconKey, nonce); // no AAD
  return new TextDecoder().decode(aead.decrypt(ct));
}
