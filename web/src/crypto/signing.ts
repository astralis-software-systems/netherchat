// Mirrors protocol/signing.go exactly (protocol v3). The signature over a message
// covers an injective, length-prefixed encoding so that no concatenation of one
// field can be confused for another. Both signer and verifier — in any language —
// must derive identical bytes, so this layout is fixed and must match the Go side
// byte-for-byte (protocol/signing_test.go and signing.test.ts pin the same hex).
//
//   field("netherchat/msg/v1") || field(room_id) || field(from_id)
//     || epoch_be64 || field(nonce) || field(ciphertext)
//
// where field(b) = uint64-big-endian(len(b)) || b, and epoch_be64 is the epoch
// as 8 bytes big-endian (NOT length-prefixed).

const DOMAIN_TAG = "netherchat/msg/v1";
const enc = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

/** 8-byte big-endian encoding of a uint64 (epoch / field length). */
export function u64be(n: number | bigint): Uint8Array {
  let x = BigInt(n);
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** field(b) = uint64-be(len) || b. */
function field(b: Uint8Array): Uint8Array {
  return concat(u64be(b.length), b);
}

export function signingBytes(
  roomID: string,
  fromID: string,
  epoch: number | bigint,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return concat(
    field(utf8(DOMAIN_TAG)),
    field(utf8(roomID)),
    field(utf8(fromID)),
    u64be(epoch),
    field(nonce),
    field(ciphertext),
  );
}
