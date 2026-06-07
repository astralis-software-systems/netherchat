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

// Frozen vector from the Go implementation (protocol v3, room-bound signature).
const VECTOR = {
  roomKey: "oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8=",
  signPub: "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=",
  roomID: "ops",
  fromID: "alice-9f3c",
  epoch: 7,
  plaintext: "the database is on fire 🔥 `kubectl rollout undo`",
  nonce: "qDNaA4QRIdnkB1MaQcH+xT3wRJd6Gi/t",
  cipher: "1UaaM3zoBV5xEWbFu6Kv2rmGz1mcSfO0R1AAVgp13rk1uRsA+25W7k9g9hJ7ANZ72mhqFOOLw+q75Z36k+e18FLjdg==",
  sig: "5sk4OPsflCQ2El+peDpLIPmlJT66qTAUujHvJ5L9/BvR5FAcHuNWmPURtgBc/E9QVbakL0++Bj0rQ1Zk4VDnAA==",
};

describe("Go ↔ browser byte interop", () => {
  it("decrypts and verifies a message sealed by the Go TUI", () => {
    const rk = { epoch: VECTOR.epoch, key: fromB64(VECTOR.roomKey) };
    const pt = openMessage(
      rk,
      fromB64(VECTOR.signPub),
      VECTOR.roomID,
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
      openMessage(rk, fromB64(VECTOR.signPub), VECTOR.roomID, VECTOR.fromID, VECTOR.epoch, fromB64(VECTOR.nonce), ct, fromB64(VECTOR.sig)),
    ).toThrow();
  });

  it("rejects a wrong room id (the signature binds it)", () => {
    const rk = { epoch: VECTOR.epoch, key: fromB64(VECTOR.roomKey) };
    expect(() =>
      openMessage(rk, fromB64(VECTOR.signPub), "other-room", VECTOR.fromID, VECTOR.epoch, fromB64(VECTOR.nonce), fromB64(VECTOR.cipher), fromB64(VECTOR.sig)),
    ).toThrow();
  });

  it("rejects the wrong epoch in the AEAD additional data", () => {
    const rk = { epoch: 8, key: fromB64(VECTOR.roomKey) }; // wrong epoch
    expect(() =>
      openMessage(rk, fromB64(VECTOR.signPub), VECTOR.roomID, VECTOR.fromID, 8, fromB64(VECTOR.nonce), fromB64(VECTOR.cipher), fromB64(VECTOR.sig)),
    ).toThrow();
  });
});

describe("browser crypto round-trips (post-refactor sanity)", () => {
  const utf8 = (s: string) => new TextEncoder().encode(s);

  it("seals and opens a message", () => {
    const id = newEphemeralIdentity();
    const rk = newRoomKey(0);
    const sealed = sealMessage(id, rk, "ops", "me", utf8("hello, war room"));
    const pt = openMessage(rk, id.signPub, "ops", "me", rk.epoch, sealed.nonce, sealed.ciphertext, sealed.signature);
    expect(new TextDecoder().decode(pt)).toBe("hello, war room");
  });

  it("accepts a message with no signature as unsigned", () => {
    const id = newEphemeralIdentity();
    const rk = newRoomKey(0);
    const sealed = sealMessage(id, rk, "ops", "me", utf8("legacy"));
    // Empty signature → decrypt without verification (no throw).
    const pt = openMessage(rk, id.signPub, "ops", "me", rk.epoch, sealed.nonce, sealed.ciphertext, new Uint8Array(0));
    expect(new TextDecoder().decode(pt)).toBe("legacy");
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
