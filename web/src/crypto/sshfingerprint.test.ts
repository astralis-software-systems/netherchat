import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sshFingerprint, fingerprint, newEphemeralIdentity } from "./identity";
import { fromB64 } from "./base64";

// The subject join, pinned against Go. The vectors come from
// tui/e2e/attribution_vectors_test.go, which computes them with the same
// crypto.Fingerprint the wire and the attestations use.

interface VectorFile {
  fingerprintVectors: { publicKeyB64: string; fingerprint: string }[];
}

function vectors(): VectorFile {
  const path = fileURLToPath(new URL("../net/testdata/attribution.json", import.meta.url));
  return JSON.parse(readFileSync(path, "utf8")) as VectorFile;
}

describe("sshFingerprint", () => {
  it("matches Go on every vector, including the all-zero key", () => {
    const v = vectors().fingerprintVectors;
    expect(v.length).toBeGreaterThanOrEqual(4);
    for (const tc of v) {
      expect(sshFingerprint(fromB64(tc.publicKeyB64)), tc.publicKeyB64).toBe(tc.fingerprint);
    }
  });

  it("produces the SSH dialect an attestation's subject is written in", () => {
    const fpr = sshFingerprint(newEphemeralIdentity().signPub);
    // "SHA256:" + 43 chars of unpadded standard base64 over a 32-byte digest.
    expect(fpr).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
  });

  it("is not the short hex fingerprint, which is a different thing entirely", () => {
    // The doc comment on `fingerprint` claimed for a long time that it matched
    // Go's crypto.Fingerprint. It never did, and nothing checked.
    const id = newEphemeralIdentity();
    expect(sshFingerprint(id.signPub)).not.toBe(fingerprint(id.signPub));
  });
});
