import { describe, expect, it } from "vitest";
import config from "./vite.config";

// THE BUILT BUNDLE MUST BE ABLE TO REACH A RELAY.
//
// `vite preview` serves web/dist — the bytes a self-hoster deploys — and it is the
// only way to exercise them locally before they go behind a real reverse proxy.
// Reaching a relay through it needs the /ws proxy (with the Origin rewrite the
// relay's same-origin handshake check requires) and the /beacon/ proxy.
//
// Vite resolves `proxy: preview?.proxy ?? server.proxy`: an ABSENT preview.proxy
// inherits the dev one whole, which is why preview has always worked despite six
// roadmap revisions saying it could not. But that `??` is a whole-object fallback
// and not a merge — one unrelated preview.proxy entry silently drops /ws, and the
// failure shows up as a browser client that works in dev and hangs on the built
// bundle. This test is what turns that from a trap into a red build.

describe("vite config", () => {
  const server = config.server;
  const preview = config.preview;

  it("gives the preview server the same proxy as the dev server", () => {
    expect(server?.proxy).toBeDefined();
    expect(preview?.proxy).toBeDefined();
    // Identity, not deep equality: two objects that happen to match today are two
    // objects that can stop matching, and the Origin rewrite is the half that
    // would be quietly dropped.
    expect(preview?.proxy).toBe(server?.proxy);
  });

  it("proxies both relay paths a browser client needs", () => {
    for (const surface of [server?.proxy, preview?.proxy]) {
      expect(Object.keys(surface ?? {})).toEqual(expect.arrayContaining(["/ws", "/beacon/"]));
    }
  });

  it("upgrades websockets and rewrites Origin on /ws", () => {
    const ws = (preview?.proxy as Record<string, { ws?: boolean; changeOrigin?: boolean; configure?: unknown }>)["/ws"];
    expect(ws.ws).toBe(true);
    expect(ws.changeOrigin).toBe(true);
    // The Origin rewrite is a `configure` hook. Without it the relay refuses the
    // handshake from a differently-ported dev or preview server, and the symptom
    // is a socket that opens and immediately closes.
    expect(typeof ws.configure).toBe("function");
  });
});
