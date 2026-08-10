import { defineConfig, type Connect, type Plugin } from "vite";
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
    proxy: {
      // WebSocket relay. `changeOrigin` rewrites the upstream Host header; we
      // additionally rewrite the Origin header so the relay's same-origin
      // handshake check (Origin host == Host) succeeds in dev.
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
      // segment distinguishes it from the "/beacon" page (rewritten to beacon.html
      // by cleanRoutes), so the page and the API coexist on one origin.
      "/beacon/": { target: RELAY, changeOrigin: true },
    },
  },
});
