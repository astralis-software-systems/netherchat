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
 * A short, human-readable fingerprint of an Ed25519 public key: SHA-256 of the
 * RAW key, first 16 bytes as 8 colon-separated upper-case hex pairs.
 *
 * This is NOT the fingerprint the rest of the system uses, and the comment that
 * used to say it matched `crypto.Fingerprint` in Go was wrong. Go's is
 * `ssh.FingerprintSHA256`, over the SSH wire encoding of the key, rendered as
 * `SHA256:<unpadded base64>` — a different digest input and a different
 * alphabet. See sshFingerprint below, which is the one that matches and the one
 * an attestation's `subject` is written in. This function is used nowhere but
 * its own test; it is kept because a short hex fingerprint is the readable form
 * for a human comparing two screens, and renamed nothing so no caller moves.
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

/**
 * The SSH SHA-256 fingerprint of an Ed25519 public key — byte-for-byte what Go's
 * `crypto.Fingerprint` (`ssh.FingerprintSHA256`) produces, and the dialect an
 * identity attestation writes its `subject` in.
 *
 * It exists so this client can make the one check about a carried credential
 * that needs no issuer key and no clock: is this statement even about the key it
 * arrived on? An attestation is not a secret, so anyone who has seen one can
 * attach it to their own Hello; without this join, a credential naming the CEO
 * would sit beside any key at all.
 *
 * The digest is over the SSH wire encoding, not the raw key:
 *
 *   string("ssh-ed25519") || string(pubkey)
 *
 * where `string(x)` is a 4-byte big-endian length followed by the bytes. Then
 * `SHA256:` + standard base64 with the `=` padding stripped, which is what
 * OpenSSH prints. Pinned against Go's output by the fingerprintVectors in
 * src/net/testdata/attribution.json — a derivation that was subtly wrong would
 * turn every credential into a mismatch, and a check that always says "no" looks
 * like caution while being broken.
 */
export function sshFingerprint(signPub: Uint8Array): string {
  const algo = new TextEncoder().encode("ssh-ed25519");
  const blob = new Uint8Array(4 + algo.length + 4 + signPub.length);
  const view = new DataView(blob.buffer);
  let off = 0;
  view.setUint32(off, algo.length, false);
  off += 4;
  blob.set(algo, off);
  off += algo.length;
  view.setUint32(off, signPub.length, false);
  off += 4;
  blob.set(signPub, off);

  let bin = "";
  for (const b of sha256(blob)) bin += String.fromCharCode(b);
  return "SHA256:" + btoa(bin).replace(/=+$/, "");
}
