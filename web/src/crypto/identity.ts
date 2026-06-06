// Ephemeral session identity for the link-join client.
//
// Unlike the TUI (which stores a long-term identity in identity.json) and unlike
// the old persistent web client, the join client generates a FRESH identity in
// memory on every visit and never writes it anywhere — no localStorage, no
// cookies, nothing. Close the tab and the keys are gone. There is no account, no
// recovery, and no cross-visit linkability: that is the whole point of a
// drop-in-via-link war room.
//
//   - Ed25519 (tweetnacl nacl.sign)  identity, signatures, fingerprint
//   - X25519  (tweetnacl nacl.box)   receiving wrapped room keys
//
// tweetnacl's 64-byte sign secret key has the same layout as Go's
// ed25519.PrivateKey (seed || public), and nacl.box implements the same NaCl
// crypto_box as golang.org/x/crypto/nacl/box, so signatures and key-wraps
// interoperate byte-for-byte with the Go TUI clients sharing the room.

import nacl from "tweetnacl";
import { sha256 } from "@noble/hashes/sha256";

export interface Identity {
  signPub: Uint8Array; // Ed25519 public  (32 bytes)
  signSecret: Uint8Array; // Ed25519 secret  (64 bytes: seed || public)
  kxPub: Uint8Array; // X25519 public   (32 bytes)
  kxSecret: Uint8Array; // X25519 secret   (32 bytes)
}

/**
 * Generate a brand-new ephemeral identity from the platform CSPRNG. Call this
 * once per visit; do not persist the result.
 */
export function newEphemeralIdentity(): Identity {
  const sign = nacl.sign.keyPair();
  const box = nacl.box.keyPair();
  return {
    signPub: sign.publicKey,
    signSecret: sign.secretKey,
    kxPub: box.publicKey,
    kxSecret: box.secretKey,
  };
}

/**
 * Human-readable fingerprint of an Ed25519 public key, matching
 * crypto.Fingerprint in Go: SHA-256 of the key, first 16 bytes rendered as 8
 * colon-separated upper-case hex pairs.
 */
export function fingerprint(signPub: Uint8Array): string {
  const sum = sha256(signPub);
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) {
    parts.push(hex2(sum[i * 2]) + hex2(sum[i * 2 + 1]));
  }
  return parts.join(":").toUpperCase();
}

function hex2(b: number): string {
  return b.toString(16).padStart(2, "0");
}
