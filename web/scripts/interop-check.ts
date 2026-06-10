// Standalone interop check (no test runner): decrypts the Go-produced vector and
// runs the browser crypto round-trips. Run with: npx vite-node scripts/interop-check.ts
// (a worker-free alternative to vitest for restricted environments).
import { fromB64, toB64 } from "../src/crypto/base64";
import { newRoomKey, ratchet, wrapRoomKey, unwrapRoomKey, sealMessage, openMessage } from "../src/crypto/group";
import { newEphemeralIdentity, fingerprint } from "../src/crypto/identity";
import { signingBytes } from "../src/crypto/signing";
import { deriveBeaconKey, openBeacon } from "../src/crypto/beacon";

// Protocol v3 vector (room-bound signature) from protocol's TestGenInteropVector.
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

let failures = 0;
function check(name: string, ok: boolean) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) failures++;
}

// 1. Decrypt + verify the Go-sealed v3 message.
const rk = { epoch: VECTOR.epoch, key: fromB64(VECTOR.roomKey) };
const pt = openMessage(rk, fromB64(VECTOR.signPub), VECTOR.roomID, VECTOR.fromID, VECTOR.epoch, fromB64(VECTOR.nonce), fromB64(VECTOR.cipher), fromB64(VECTOR.sig));
check("decrypts Go-sealed message", new TextDecoder().decode(pt) === VECTOR.plaintext);

// 2. Tampered ciphertext is rejected.
{
  const ct = fromB64(VECTOR.cipher);
  ct[0] ^= 0x01;
  let threw = false;
  try { openMessage(rk, fromB64(VECTOR.signPub), VECTOR.roomID, VECTOR.fromID, VECTOR.epoch, fromB64(VECTOR.nonce), ct, fromB64(VECTOR.sig)); } catch { threw = true; }
  check("rejects tampered ciphertext", threw);
}

// 3. A wrong room id is rejected (the signature binds it).
{
  let threw = false;
  try { openMessage(rk, fromB64(VECTOR.signPub), "other-room", VECTOR.fromID, VECTOR.epoch, fromB64(VECTOR.nonce), fromB64(VECTOR.cipher), fromB64(VECTOR.sig)); } catch { threw = true; }
  check("rejects wrong room id", threw);
}

// 4. signingBytes matches the Go cross-impl vector byte-for-byte.
{
  const nonce = new Uint8Array(24);
  for (let i = 0; i < 24; i++) nonce[i] = i;
  const hex = Array.from(signingBytes("ops", "alice", 7, nonce, new TextEncoder().encode("netherchat")))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
  const want =
    "00000000000000116e6574686572636861742f6d73672f7631" +
    "00000000000000036f7073" +
    "0000000000000005616c696365" +
    "0000000000000007" +
    "0000000000000018000102030405060708090a0b0c0d0e0f1011121314151617" +
    "000000000000000a6e657468657263686174";
  check("signingBytes matches Go", hex === want);
}

// 5. Round-trip seal/open (v3, room-bound).
{
  const id = newEphemeralIdentity();
  const k = newRoomKey(0);
  const s = sealMessage(id, k, "ops", "me", new TextEncoder().encode("hello, war room"));
  const out = openMessage(k, id.signPub, "ops", "me", k.epoch, s.nonce, s.ciphertext, s.signature);
  check("seal/open round-trip", new TextDecoder().decode(out) === "hello, war room");
}

// 6. Unsigned message accepted (empty signature → decrypt without verify).
{
  const id = newEphemeralIdentity();
  const k = newRoomKey(0);
  const s = sealMessage(id, k, "ops", "me", new TextEncoder().encode("legacy"));
  const out = openMessage(k, id.signPub, "ops", "me", k.epoch, s.nonce, s.ciphertext, new Uint8Array(0));
  check("accepts unsigned message", new TextDecoder().decode(out) === "legacy");
}

// 7. Wrap/unwrap a room key.
{
  const a = newEphemeralIdentity();
  const b = newEphemeralIdentity();
  const k = newRoomKey(3);
  const { nonce, wrapped } = wrapRoomKey(a, k, b.kxPub);
  const got = unwrapRoomKey(b, k.epoch, nonce, wrapped, a.kxPub);
  check("wrap/unwrap room key", got.key.every((v, i) => v === k.key[i]));
}

// 8. Deterministic ratchet + fingerprint format + fresh identities.
{
  const k = newRoomKey(0);
  const n1 = ratchet(k), n2 = ratchet(k);
  check("deterministic ratchet", n1.epoch === 1 && n1.key.every((v, i) => v === n2.key[i]));
  const id = newEphemeralIdentity();
  check("fingerprint format", /^[0-9A-F]{4}(:[0-9A-F]{4}){7}$/.test(fingerprint(id.signPub)));
  check("fresh identity each call", !newEphemeralIdentity().signPub.every((v, i) => v === id.signPub[i]));
}

// 9. Status Beacon (§1.2): the browser derives the same beacon key Go does and
// decrypts a Go-sealed beacon blob — proving the beacon link reads what the TUI
// wrote. Vector from crypto's TestGenBeaconInteropVector (room key 0x00..0x1f).
const BEACON = {
  beaconKeyB64: "o4qq5R8jF5zoXjiPj3reJsRFk/3Iok9ZFyJR0PJSAQQ=",
  status: "SEV1 declared, cause under investigation",
  blobB64:
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXS7PWgytZDWAVsDrYMITE9OUrOPwZG3lWI/MvHt45gZZR5pZiyVYm/8+S9ocwrYnsP8ONSBOz3IE=",
};
{
  const roomKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) roomKey[i] = i;
  check("derives Go beacon key", toB64(deriveBeaconKey(roomKey)) === BEACON.beaconKeyB64);

  const text = openBeacon(fromB64(BEACON.beaconKeyB64), fromB64(BEACON.blobB64));
  check("decrypts Go-sealed beacon", text === BEACON.status);

  // The message room key cannot read the beacon — a beacon reader never sees msgs.
  let threw = false;
  try {
    openBeacon(roomKey, fromB64(BEACON.blobB64));
  } catch {
    threw = true;
  }
  check("room key cannot read beacon", threw);
}

console.log(failures === 0 ? "\nALL INTEROP CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
