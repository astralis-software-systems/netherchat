// CSPRNG bytes from the platform. globalThis.crypto.getRandomValues exists in
// every modern browser and in Node 18+ (used by the test runner).

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}
