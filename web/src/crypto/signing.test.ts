// Cross-implementation contract: signingBytes here must produce the EXACT same
// bytes as protocol.SigningBytes in Go (protocol/signing_test.go pins the same
// hex). If the two ever diverge, signatures stop verifying across Go and the
// browser and one of these tests fails.

import { describe, it, expect } from "vitest";
import { signingBytes } from "./signing";

function toHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

describe("SigningBytes cross-implementation vector", () => {
  it("matches protocol/signing_test.go byte-for-byte", () => {
    const nonce = new Uint8Array(24);
    for (let i = 0; i < 24; i++) nonce[i] = i;
    const ciphertext = new TextEncoder().encode("netherchat");

    const got = toHex(signingBytes("ops", "alice", 7, nonce, ciphertext));
    const want =
      "00000000000000116e6574686572636861742f6d73672f7631" + // field("netherchat/msg/v1")
      "00000000000000036f7073" + // field("ops")
      "0000000000000005616c696365" + // field("alice")
      "0000000000000007" + // epoch 7, big-endian
      "0000000000000018000102030405060708090a0b0c0d0e0f1011121314151617" + // field(nonce)
      "000000000000000a6e657468657263686174"; // field("netherchat")

    expect(got).toBe(want);
  });
});
