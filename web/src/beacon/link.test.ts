import { describe, it, expect } from "vitest";
import { parseBeaconLink, linkProblem, type BeaconLinkProblem } from "./link";
import { toB64 } from "../crypto/base64";

// The security property under test (§1.2, docs/encryption.md): the beacon key is
// read from the URL FRAGMENT and never from the query string, so it is never sent
// to the relay. main.ts itself is a DOM entry point with top-level side effects, so
// these cover the layer below it: the pure parse that decides what is usable.

/** A valid 32-byte key whose standard base64 contains both "+" and "/". */
function trickyKey(): Uint8Array {
  return new Uint8Array(32).fill(0xfb);
}

describe("parseBeaconLink", () => {
  it("reads the key from the fragment", () => {
    const key = trickyKey();
    const link = parseBeaconLink("?room=ops&ttl=7200", "#key=" + encodeURIComponent(toB64(key)));
    expect(link.ok).toBe(true);
    if (!link.ok) return;
    expect(link.room).toBe("ops");
    expect(Array.from(link.key)).toEqual(Array.from(key));
  });

  it("round-trips a key containing + and / through the fragment", () => {
    const b64 = toB64(trickyKey());
    expect(b64).toContain("+"); // the encoding hazard this guards
    expect(b64).toContain("/");
    const link = parseBeaconLink("?room=ops", "#key=" + encodeURIComponent(b64));
    expect(link.ok).toBe(true);
    if (link.ok) expect(toB64(link.key)).toBe(b64);
  });

  it("restores a '+' that form-decoding turned into a space", () => {
    // A hand-edited link may carry raw base64 in the fragment; URLSearchParams
    // form-decodes "+" to a space. Base64 has no spaces, so restoring is safe.
    const b64 = toB64(trickyKey());
    const link = parseBeaconLink("?room=ops", "#key=" + b64);
    expect(link.ok).toBe(true);
    if (link.ok) expect(toB64(link.key)).toBe(b64);
  });

  it("takes the room from the fragment when the query has none", () => {
    const link = parseBeaconLink("", "#room=ops&key=" + encodeURIComponent(toB64(trickyKey())));
    expect(link.ok).toBe(true);
    if (link.ok) expect(link.room).toBe("ops");
  });

  // --- fail closed ----------------------------------------------------------

  it("REFUSES a key in the query string", () => {
    const link = parseBeaconLink("?room=ops&key=" + encodeURIComponent(toB64(trickyKey())), "");
    expect(link).toEqual({ ok: false, problem: "key-in-query" });
  });

  it("REFUSES a query key even when a valid fragment key is also present", () => {
    const b64 = encodeURIComponent(toB64(trickyKey()));
    const link = parseBeaconLink("?room=ops&key=" + b64, "#key=" + b64);
    expect(link).toEqual({ ok: false, problem: "key-in-query" });
  });

  it("fails closed on a missing key", () => {
    expect(parseBeaconLink("?room=ops", "")).toEqual({ ok: false, problem: "missing-key" });
    expect(parseBeaconLink("?room=ops", "#key=")).toEqual({ ok: false, problem: "missing-key" });
  });

  it("fails closed on a missing room", () => {
    expect(parseBeaconLink("", "#key=" + encodeURIComponent(toB64(trickyKey())))).toEqual({
      ok: false,
      problem: "missing-room",
    });
    expect(parseBeaconLink("?room=%20%20", "#key=x")).toEqual({ ok: false, problem: "missing-room" });
  });

  it("reports the query key first when the link is broken in several ways", () => {
    // The security-relevant refusal outranks a merely incomplete link.
    expect(parseBeaconLink("?key=" + encodeURIComponent(toB64(trickyKey())), "")).toEqual({
      ok: false,
      problem: "key-in-query",
    });
  });

  it("fails closed on a key that is not base64", () => {
    expect(parseBeaconLink("?room=ops", "#key=!!!not-base64!!!")).toEqual({ ok: false, problem: "bad-key" });
  });

  it("fails closed on a key that is not 32 bytes", () => {
    const short = toB64(new Uint8Array(16).fill(7));
    expect(parseBeaconLink("?room=ops", "#key=" + encodeURIComponent(short))).toEqual({ ok: false, problem: "bad-key" });
    const long = toB64(new Uint8Array(33).fill(7));
    expect(parseBeaconLink("?room=ops", "#key=" + encodeURIComponent(long))).toEqual({ ok: false, problem: "bad-key" });
  });

  it("tolerates search/hash with or without their leading punctuation", () => {
    const k = encodeURIComponent(toB64(trickyKey()));
    expect(parseBeaconLink("room=ops", "key=" + k).ok).toBe(true);
    expect(parseBeaconLink("?room=ops", "#key=" + k).ok).toBe(true);
  });
});

describe("linkProblem", () => {
  const problems: BeaconLinkProblem[] = ["missing-room", "key-in-query", "missing-key", "bad-key"];

  it("gives every problem a legible headline and detail", () => {
    for (const p of problems) {
      const [headline, detail] = linkProblem(p);
      expect(headline.length).toBeGreaterThan(0);
      expect(detail.length).toBeGreaterThan(0);
    }
  });

  it("tells a reader with an old-format link that the key is exposed", () => {
    const [, detail] = linkProblem("key-in-query");
    expect(detail).toMatch(/relay/);
    expect(detail).toMatch(/exposed/);
  });
});

// The cross-language contract: this exact string is what Go's beaconLinkURL emits,
// asserted byte-for-byte by TestBeaconLinkURLMatchesWebVector in
// cmd/netherchat/beaconcmd_test.go. If one side changes shape, one of the two fails.
const GO_LINK_VECTOR = {
  url: "https://chat.example.com/beacon?room=ops&ttl=7200#key=o4qq5R8jF5zoXjiPj3reJsRFk%2F3Iok9ZFyJR0PJSAQQ%3D",
  room: "ops",
  keyB64: "o4qq5R8jF5zoXjiPj3reJsRFk/3Iok9ZFyJR0PJSAQQ=",
};

describe("the link Go actually builds", () => {
  it("parses, with the key recovered from the fragment", () => {
    const u = new URL(GO_LINK_VECTOR.url);
    expect(u.search).not.toContain("key");
    const link = parseBeaconLink(u.search, u.hash);
    expect(link.ok).toBe(true);
    if (!link.ok) return;
    expect(link.room).toBe(GO_LINK_VECTOR.room);
    expect(toB64(link.key)).toBe(GO_LINK_VECTOR.keyB64);
  });
});
