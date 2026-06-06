// Standard base64 (with padding, +/ alphabet) — the encoding Go's encoding/json
// uses for []byte fields. Every binary field on the wire (keys, nonces,
// ciphertext, signatures) crosses as a standard-base64 string, so the web client
// must encode/decode the same way to interoperate with the Go TUI and server.

export function toB64(bytes: Uint8Array): string {
  let bin = "";
  // Chunk to avoid blowing the argument limit of String.fromCharCode on large
  // payloads (messages can be up to ~1 MiB).
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
