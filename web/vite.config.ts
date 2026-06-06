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

// joinRoute serves the join client at the clean "/join" path (its file is
// join.html) in both the dev server and `vite preview`, preserving the query
// string that carries ?room=…&token=….
function joinRoute(): Plugin {
  const rewrite = (req: Connect.IncomingMessage): void => {
    const url = req.url ?? "";
    if (url === "/join" || url.startsWith("/join?")) {
      req.url = "/join.html" + url.slice("/join".length);
    }
  };
  return {
    name: "netherchat-join-route",
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
  plugins: [joinRoute()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        join: resolve(__dirname, "join.html"),
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
    },
  },
});
