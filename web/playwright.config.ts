import { defineConfig } from "@playwright/test";

// Playwright drives ONE test suite here: e2e/interop-live.pwtest.ts, the only place
// in this repo where a real relay, a real browser client and a real Go client are
// alive at the same time. Everything else about the web client is covered by
// vitest, which is faster and needs no browser; do not migrate those here.
//
// `.pwtest.ts` rather than `.spec.ts` on purpose: vitest's default include matches
// `*.test.*` and `*.spec.*`, and this suite must never be picked up by `npm test` —
// it spawns processes, builds Go binaries, and takes tens of seconds.
export default defineConfig({
  testDir: "e2e",
  testMatch: /.*\.pwtest\.ts$/,

  // One relay, one room namespace, and legs whose ordering is the thing under
  // test. Parallelism here would not be faster, only nondeterministic.
  fullyParallel: false,
  workers: 1,
  retries: 0,

  // Generous: the hooks build two Go binaries and start two servers.
  timeout: 180_000,
  expect: { timeout: 20_000 },

  reporter: [["list"]],
  use: { headless: true },
});
