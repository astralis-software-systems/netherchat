// Where does the join client's WebSocket point?
//
// It used to be answerable from the link: `/join?…&server=wss://elsewhere/ws`
// aimed the socket at any host the sender named, on the genuine origin behind
// genuine TLS. The consequence was not merely a bad connection — a relay that
// answers `you_are_first` gets a freshly minted room key, and the ordinary
// key-exchange path (client.ts `onKeyRequest`) then wraps that key for any member
// the relay announces, with no consent step and the status line reading
// "end-to-end encrypted" throughout.
//
// The parameter is gone. What is pinned below is the invariant that replaced it:
// the relay is derived from the page ORIGIN alone, so no query string — under any
// parameter name — can move it. These cases deliberately feed pageRelay() the
// hostile URL in full; a resolver that never sees the query would make the test
// vacuous.
//
// The wiring in join/main.ts (`pageRelay()` → `new NetherClient(relay.url, …)`)
// is NOT covered here and is deliberately not faked: vitest runs in the node
// environment (no `test` block in vite.config.ts) and web/ has no jsdom or
// happy-dom dependency, so that module — which reads `location` and `document` at
// import time — cannot be loaded. pageRelay() takes the page URL as a parameter
// precisely so the decision it makes is testable one layer below the DOM.

import { describe, it, expect } from "vitest";
import { pageRelay } from "./protocol";

const EVIL = "wss://evil.example/ws";

describe("pageRelay", () => {
  it("derives the relay from the origin that served the page", () => {
    expect(pageRelay("https://chat.example.com/join?room=ops&token=t")).toEqual({
      url: "wss://chat.example.com/ws",
      host: "chat.example.com",
    });
  });

  it("ignores ?server=, the parameter that used to redirect the socket", () => {
    const relay = pageRelay(
      `https://chat.example.com/join?room=ops&token=t&server=${encodeURIComponent(EVIL)}`,
    );
    expect(relay.url).toBe("wss://chat.example.com/ws");
    expect(relay.url).not.toContain("evil");
    expect(relay.host).toBe("chat.example.com");
  });

  it("ignores a hostile endpoint under any parameter name", () => {
    for (const name of ["server", "Server", "SERVER", "relay", "ws", "url", "host", "wsUrl"]) {
      const relay = pageRelay(`https://chat.example.com/join?room=ops&${name}=${encodeURIComponent(EVIL)}`);
      expect(relay).toEqual({ url: "wss://chat.example.com/ws", host: "chat.example.com" });
    }
  });

  it("ignores an unencoded value, which URL parsing leaves partly intact", () => {
    // `server=wss://evil.example/ws` unescaped: the old resolver read this happily.
    const relay = pageRelay("https://chat.example.com/join?room=ops&server=wss://evil.example/ws");
    expect(relay.url).toBe("wss://chat.example.com/ws");
  });

  it("ignores a scheme-relative and a bare-host value", () => {
    // normalizeWsUrl() used to accept both of these, inventing a scheme for the
    // second — the reason a value that does not even look like a URL was enough.
    expect(pageRelay("https://chat.example.com/join?server=//evil.example/ws").url)
      .toBe("wss://chat.example.com/ws");
    expect(pageRelay("https://chat.example.com/join?server=evil.example:3000").url)
      .toBe("wss://chat.example.com/ws");
  });

  it("ignores the fragment as well as the query", () => {
    expect(pageRelay(`https://chat.example.com/join?room=ops#server=${EVIL}`).url)
      .toBe("wss://chat.example.com/ws");
  });

  it("reads the host, not embedded credentials that mimic one", () => {
    // `https://evil.example@chat.example.com/…` — the host is chat.example.com;
    // "evil.example" is a username, and must not become the endpoint.
    const relay = pageRelay("https://evil.example@chat.example.com/join?room=ops");
    expect(relay).toEqual({ url: "wss://chat.example.com/ws", host: "chat.example.com" });
  });

  it("keeps a non-default port", () => {
    expect(pageRelay("https://chat.example.com:8443/join?room=ops")).toEqual({
      url: "wss://chat.example.com:8443/ws",
      host: "chat.example.com:8443",
    });
  });

  it("falls back to ws:// when the page itself was served over http", () => {
    expect(pageRelay("http://localhost:5173/join?room=ops")).toEqual({
      url: "ws://localhost:5173/ws",
      host: "localhost:5173",
    });
  });

  it("always targets /ws, whatever path served the page", () => {
    for (const path of ["/join", "/join.html", "/", "/some/deep/path"]) {
      expect(pageRelay(`https://chat.example.com${path}`).url).toBe("wss://chat.example.com/ws");
    }
  });

  it("names the same endpoint it connects to", () => {
    // The label and the socket come from one call, so the UI cannot show a host
    // the connection is not using.
    const relay = pageRelay(`https://chat.example.com/join?server=${encodeURIComponent(EVIL)}`);
    expect(new URL(relay.url).host).toBe(relay.host);
  });
});
