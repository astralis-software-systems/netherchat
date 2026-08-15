// Beacon link parsing (§1.2) — kept separate from main.ts, which is a DOM entry
// point with top-level side effects and therefore not unit-testable. Everything
// that decides WHETHER a link is usable lives here, as pure functions over two
// strings, so the rules below are covered by link.test.ts without faking a DOM.
//
// THE RULE: the beacon key travels in the URL FRAGMENT, never in the query.
//
//   https://host/beacon?room=ops&ttl=7200#key=<base64 beacon key>
//
// A fragment is client-side only (RFC 3986 §3.5): the browser never puts it in a
// request line, and the Referrer Policy spec's "strip url for use as a referrer"
// algorithm drops it unconditionally, under EVERY policy. A query string does the
// opposite — this page polls a same-origin `/beacon/<room>` every 30s, and under
// the default `strict-origin-when-cross-origin` policy a same-origin request sends
// the full URL, query included, as `Referer`. A `?key=` would therefore hand the
// relay the decryption key for ciphertext it already stores, every 30 seconds.
//
// A `?key=` link is consequently REFUSED, not honoured: by the time this code runs
// the key has already been sent in the page-load request line, so reading it would
// only reward a link whose key is already burnt. Fail closed and say why.

import { fromB64 } from "../crypto/base64";

const KEY_BYTES = 32;

/** Why a beacon link could not be used. Each maps to a message via linkProblem. */
export type BeaconLinkProblem = "missing-room" | "key-in-query" | "missing-key" | "bad-key";

export type BeaconLink =
  | { ok: true; room: string; key: Uint8Array }
  | { ok: false; problem: BeaconLinkProblem };

/**
 * Parse a beacon link into a room and a 32-byte key, or a reason it is unusable.
 * Pure: `search` and `hash` are `location.search` / `location.hash` verbatim
 * (leading "?" and "#" optional).
 */
export function parseBeaconLink(search: string, hash: string): BeaconLink {
  const query = new URLSearchParams(search.replace(/^\?/, ""));
  const frag = new URLSearchParams(hash.replace(/^#/, ""));

  // Checked before anything else, so the reader always hears the reason that
  // matters: an old-format link leaked its key in the page's own request line
  // before this code ran, and honouring it here would not un-send it.
  if (query.get("key")) return { ok: false, problem: "key-in-query" };

  const room = (query.get("room") ?? frag.get("room") ?? "").trim();
  if (!room) return { ok: false, problem: "missing-room" };

  // URLSearchParams applies form decoding, which turns "+" into a space. Our own
  // links percent-encode the key so this never fires, but it makes a hand-edited
  // link (a reader moving "?key=" to "#key=" themselves) work instead of failing
  // with an unexplained decrypt error. A space is never valid in base64 anyway.
  // Restore BEFORE trimming: a base64 key may legitimately begin or end with "+".
  const keyB64 = (frag.get("key") ?? "").replace(/ /g, "+").trim();
  if (!keyB64) return { ok: false, problem: "missing-key" };

  let key: Uint8Array;
  try {
    key = fromB64(keyB64);
  } catch {
    return { ok: false, problem: "bad-key" };
  }
  if (key.length !== KEY_BYTES) return { ok: false, problem: "bad-key" };

  return { ok: true, room, key };
}

/** The reader-facing message for a problem, as [headline, detail]. */
export function linkProblem(problem: BeaconLinkProblem): [string, string] {
  switch (problem) {
    case "missing-room":
      return ["This beacon link is incomplete.", "It is missing the room it should show."];
    case "key-in-query":
      return [
        "This beacon link is an old format and will not be opened.",
        "Its key rode in the query string, so it was sent to the relay — treat it as exposed and ask for a freshly minted link.",
      ];
    case "missing-key":
      return ["This beacon link is incomplete.", "The decryption key is missing — it belongs after the # at the end of the link."];
    case "bad-key":
      return ["This beacon link is malformed.", "Its key is not a 32-byte value. The link was probably truncated in transit."];
  }
}
