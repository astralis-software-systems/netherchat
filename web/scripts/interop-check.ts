// Standalone interop check (no test runner): decrypts the Go-produced vector and
// runs the browser crypto round-trips. Run with: npx vite-node scripts/interop-check.ts
import { fromB64 } from "../src/crypto/base64";
import { newRoomKey, ratchet, wrapRoomKey, unwrapRoomKey, sealMessage, openMessage } from "../src/crypto/group";
import { newEphemeralIdentity, fingerprint } from "../src/crypto/identity";

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

let failures = 0;
function check(name: string, ok: boolean) {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) failures++;
}

// 1. Decrypt the Go-sealed message.
const rk = { epoch: VECTOR.epoch, key: fromB64(VECTOR.roomKey) };
const pt = openMessage(rk, fromB64(VECTOR.signPub), VECTOR.fromID, VECTOR.epoch, fromB64(VECTOR.nonce), fromB64(VECTOR.cipher), fromB64(VECTOR.sig));
check("decrypts Go-sealed message", new TextDecoder().decode(pt) === VECTOR.plaintext);

// 2. Tampered ciphertext is rejected.
{
  const ct = fromB64(VECTOR.cipher);
  ct[0] ^= 0x01;
  let threw = false;
  try { openMessage(rk, fromB64(VECTOR.signPub), VECTOR.fromID, VECTOR.epoch, fromB64(VECTOR.nonce), ct, fromB64(VECTOR.sig)); } catch { threw = true; }
  check("rejects tampered ciphertext", threw);
}

// 3. Round-trip seal/open.
{
  const id = newEphemeralIdentity();
  const k = newRoomKey(0);
  const s = sealMessage(id, k, "me", new TextEncoder().encode("hello, war room"));
  const out = openMessage(k, id.signPub, "me", k.epoch, s.nonce, s.ciphertext, s.signature);
  check("seal/open round-trip", new TextDecoder().decode(out) === "hello, war room");
}

// 4. Wrap/unwrap a room key.
{
  const a = newEphemeralIdentity();
  const b = newEphemeralIdentity();
  const k = newRoomKey(3);
  const { nonce, wrapped } = wrapRoomKey(a, k, b.kxPub);
  const got = unwrapRoomKey(b, k.epoch, nonce, wrapped, a.kxPub);
  check("wrap/unwrap room key", got.key.every((v, i) => v === k.key[i]));
}

// 5. Deterministic ratchet + fingerprint format + fresh identities.
{
  const k = newRoomKey(0);
  const n1 = ratchet(k), n2 = ratchet(k);
  check("deterministic ratchet", n1.epoch === 1 && n1.key.every((v, i) => v === n2.key[i]));
  const id = newEphemeralIdentity();
  check("fingerprint format", /^[0-9A-F]{4}(:[0-9A-F]{4}){7}$/.test(fingerprint(id.signPub)));
  check("fresh identity each call", !newEphemeralIdentity().signPub.every((v, i) => v === id.signPub[i]));
}

console.log(failures === 0 ? "\nALL INTEROP CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
