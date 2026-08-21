import { defineConfig, type Connect, type Plugin, type ProxyOptions } from "vite";
import { resolve } from "node:path";

// Netherchat web build.
//
// Two static entry points:
//   index.html  -> the public landing page, served at "/" (separate, already
//                  designed — not built here)
//   join.html   -> the link-join client, served at "/join"
//
// The join client speaks the EXISTING wire protocol (PROTOCOL.md) to the relay
// over a same-origin "/ws". In dev, Vite proxies "/ws" to the local relay and
// rewrites the Origin so the relay's same-origin handshake check passes. In
// production, serve this bundle and reverse-proxy "/ws" to the relay behind ONE
// origin, and map "/join" -> "/join.html" (one rewrite rule; see docs).
const RELAY = process.env.NETHERCHAT_RELAY ?? "http://localhost:3000";

// cleanRoutes serves the clean "/join" and "/beacon" paths (their files are
// join.html / beacon.html) in both the dev server and `vite preview`, preserving
// the query string (?room=…&token=… / ?room=…&key=…). Only the bare page paths are
// rewritten; the relay's REST endpoints "/beacon/<room>" (a deeper path) are NOT
// touched here and are reverse-proxied to the relay instead (see server.proxy).
function cleanRoutes(): Plugin {
  const rewrite = (req: Connect.IncomingMessage): void => {
    const url = req.url ?? "";
    for (const page of ["/join", "/beacon"]) {
      if (url === page || url.startsWith(page + "?")) {
        req.url = page + ".html" + url.slice(page.length);
        return;
      }
    }
  };
  return {
    name: "netherchat-clean-routes",
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        rewrite(req);
        next();
      });
    },
    configurePreviewServer(server) {
      server.middlewares.use((req, _res, next) => {
        rewrite(req);
        next();
      });
    },
  };
}

// relayProxy is the reverse-proxy configuration BOTH Vite servers use.
//
// IT IS DECLARED TWICE ON PURPOSE, AND NOT FOR THE REASON THAT WAS WRITTEN DOWN.
//
// It was believed for six roadmap revisions, and stated in a comment in
// e2e/interop-live.pwtest.ts, that `vite preview` "has no proxy config, so the
// built bundle cannot reach a relay through it". That is false, and was false when
// it was written: Vite resolves `proxy: preview?.proxy ?? server.proxy`, so an
// absent preview.proxy INHERITS the dev one whole. Measured, not assumed — a
// preview server on the old config upgrades ws://…/ws against a live relay and
// proxies /beacon/<room> to it, and a control config with no proxy at all serves
// the SPA for that path and refuses the socket.
//
// What IS true is the trap in that `??`. It is a whole-object fallback, not a
// merge: the day anyone adds a single unrelated preview.proxy entry, "/ws" and
// "/beacon/" vanish from preview with nothing to say so, and the failure surfaces
// as a browser client that connects in dev and hangs on the built bundle. Naming
// one object and assigning it to both makes that impossible, which is worth more
// than the line it costs. web/vite.config.test.ts fails if the two ever diverge.
//
// Neither server is the production topology. In production a reverse proxy in
// front of BOTH the static files and the relay puts them on one origin (see
// docs/self-hosting.md for the Caddy and nginx forms); these two exist so a
// developer and a self-hoster can exercise that shape locally.
const relayProxy: Record<string, string | ProxyOptions> = {
  // WebSocket relay. `changeOrigin` rewrites the upstream Host header; we
  // additionally rewrite the Origin header so the relay's same-origin handshake
  // check (Origin host == Host) succeeds against a differently-ported dev or
  // preview server.
  "/ws": {
    target: RELAY,
    ws: true,
    changeOrigin: true,
    configure: (proxy) => {
      const origin = new URL(RELAY).origin;
      proxy.on("proxyReqWs", (proxyReq) => {
        proxyReq.setHeader("origin", origin);
      });
      proxy.on("proxyReq", (proxyReq) => {
        proxyReq.setHeader("origin", origin);
      });
    },
  },
  // The beacon REST API (§1.2): GET/PUT/DELETE /beacon/<room>. The trailing
  // segment distinguishes it from the "/beacon" page (rewritten to beacon.html by
  // cleanRoutes), so the page and the API coexist on one origin.
  "/beacon/": { target: RELAY, changeOrigin: true },
};

export default defineConfig({
  plugins: [cleanRoutes()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, "index.html"),
        join: resolve(import.meta.dirname, "join.html"),
        beacon: resolve(import.meta.dirname, "beacon.html"),
      },
    },
  },
  server: {
    port: 5173,
    proxy: relayProxy,
  },
  preview: {
    port: 4173,
    proxy: relayProxy,
  },
});
