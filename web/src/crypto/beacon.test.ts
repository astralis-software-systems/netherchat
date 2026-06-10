import { describe, it, expect } from "vitest";
import { fromB64, toB64 } from "./base64";
import { deriveBeaconKey, openBeacon } from "./beacon";

// Status Beacon interop (§1.2). Vector from crypto's TestGenBeaconInteropVector
// (room key 0x00..0x1f). Proves the browser reader decrypts exactly what the Go TUI
// sealed, using the same beacon key. (In restricted environments run the worker-free
// `npm run test:node` instead of vitest.)
const BEACON = {
  beaconKeyB64: "o4qq5R8jF5zoXjiPj3reJsRFk/3Iok9ZFyJR0PJSAQQ=",
  status: "SEV1 declared, cause under investigation",
  blobB64:
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXS7PWgytZDWAVsDrYMITE9OUrOPwZG3lWI/MvHt45gZZR5pZiyVYm/8+S9ocwrYnsP8ONSBOz3IE=",
};

function knownRoomKey(): Uint8Array {
  const rk = new Uint8Array(32);
  for (let i = 0; i < 32; i++) rk[i] = i;
  return rk;
}

describe("status beacon interop", () => {
  it("derives the same beacon key as Go", () => {
    expect(toB64(deriveBeaconKey(knownRoomKey()))).toBe(BEACON.beaconKeyB64);
  });

  it("decrypts a Go-sealed beacon with the link key", () => {
    expect(openBeacon(fromB64(BEACON.beaconKeyB64), fromB64(BEACON.blobB64))).toBe(BEACON.status);
  });

  it("the message room key cannot read the beacon (distinct keys)", () => {
    expect(() => openBeacon(knownRoomKey(), fromB64(BEACON.blobB64))).toThrow();
  });

  it("rejects a tampered blob", () => {
    const blob = fromB64(BEACON.blobB64);
    blob[blob.length - 1] ^= 0xff;
    expect(() => openBeacon(fromB64(BEACON.beaconKeyB64), blob)).toThrow();
  });
});
