// Cross-language byte-interop test. The vector below is produced by the Go TUI's
// crypto (tui/internal/crypto, TestGenInteropVector) — a real XChaCha20-Poly1305
// message sealed under a fixed room key and signed with Ed25519. If the browser
// crypto here can decrypt and verify these exact bytes, the web join client and a
// Go TUI client genuinely share a room. Regenerate with:
//
//   GEN_INTEROP=1 go test ./tui/internal/crypto -run TestGenInteropVector -v

import { describe, it, expect } from "vitest";
import { fromB64 } from "./base64";
import { newRoomKey, ratchet, wrapRoomKey, unwrapRoomKey, sealMessage, openMessage } from "./group";
import { newEphemeralIdentity, fingerprint } from "./identity";

// Frozen vector from the Go implementation.
const VECTOR = {
  roomKey: "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=",
  signPub: "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=",
  fromID: "alice-9f3c",
  epoch: 7,
  plaintext: "the database is on fire 🔥 `kubectl rollout undo`",
  nonce: "ceQjYZoWpcTEQ5lMiv8Xs+HKFt3YmqAn",
  cipher: "AUSDiEknyHYuqxhB4IUH0WLAgjJZSbNWS1ZA34FUEt80F5uClGDTJgYPv1TT2LfPEk2OwcEGss1Y81UB83yi0WN6Gw==",
  sig: "Ge5CHGhYMkjs61lXBzuvUin7dW1QTZ3/0KIzojr1CDNH6H50uTTdLQcuBeK+rd94WDrFNdJfNLk5BFsH7zrCAQ==",
};

describe("Go ↔ browser byte interop", () => {
  it("decrypts and verifies a message sealed by the Go TUI", () => {
    const rk = { epoch: VECTOR.epoch, key: fromB64(VECTOR.roomKey) };
    const pt = openMessage(
      rk,
      fromB64(VECTOR.signPub),
      VECTOR.fromID,
      VECTOR.epoch,
      fromB64(VECTOR.nonce),
      fromB64(VECTOR.cipher),
      fromB64(VECTOR.sig),
    );
    expect(new TextDecoder().decode(pt)).toBe(VECTOR.plaintext);
  });

  it("rejects a tampered ciphertext (signature covers it)", () => {
    const rk = { epoch: VECTOR.epoch, key: fromB64(VECTOR.roomKey) };
    const ct = fromB64(VECTOR.cipher);
    ct[0] ^= 0x01; // flip one bit
    expect(() =>
      openMessage(rk, fromB64(VECTOR.signPub), VECTOR.fromID, VECTOR.epoch, fromB64(VECTOR.nonce), ct, fromB64(VECTOR.sig)),
    ).toThrow();
  });

  it("rejects the wrong epoch in the AEAD additional data", () => {
    const rk = { epoch: 8, key: fromB64(VECTOR.roomKey) }; // wrong epoch
    expect(() =>
      openMessage(rk, fromB64(VECTOR.signPub), VECTOR.fromID, 8, fromB64(VECTOR.nonce), fromB64(VECTOR.cipher), fromB64(VECTOR.sig)),
    ).toThrow();
  });
});

describe("browser crypto round-trips (post-refactor sanity)", () => {
  const utf8 = (s: string) => new TextEncoder().encode(s);

  it("seals and opens a message", () => {
    const id = newEphemeralIdentity();
    const rk = newRoomKey(0);
    const sealed = sealMessage(id, rk, "me", utf8("hello, war room"));
    const pt = openMessage(rk, id.signPub, "me", rk.epoch, sealed.nonce, sealed.ciphertext, sealed.signature);
    expect(new TextDecoder().decode(pt)).toBe("hello, war room");
  });

  it("wraps and unwraps a room key between two identities", () => {
    const a = newEphemeralIdentity();
    const b = newEphemeralIdentity();
    const rk = newRoomKey(3);
    const { nonce, wrapped } = wrapRoomKey(a, rk, b.kxPub);
    const got = unwrapRoomKey(b, rk.epoch, nonce, wrapped, a.kxPub);
    expect(Array.from(got.key)).toEqual(Array.from(rk.key));
  });

  it("ratchets deterministically", () => {
    const rk = newRoomKey(0);
    const n1 = ratchet(rk);
    const n2 = ratchet(rk);
    expect(n1.epoch).toBe(1);
    expect(Array.from(n1.key)).toEqual(Array.from(n2.key));
  });

  it("produces a stable, well-formed fingerprint", () => {
    const id = newEphemeralIdentity();
    expect(fingerprint(id.signPub)).toBe(fingerprint(id.signPub));
    expect(fingerprint(id.signPub)).toMatch(/^[0-9A-F]{4}(:[0-9A-F]{4}){7}$/);
  });

  it("generates a fresh identity each visit (no persistence)", () => {
    const a = newEphemeralIdentity();
    const b = newEphemeralIdentity();
    expect(Array.from(a.signPub)).not.toEqual(Array.from(b.signPub));
  });
});
