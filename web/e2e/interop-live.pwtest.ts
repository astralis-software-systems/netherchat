// Harness A — a real relay, a real browser client, and a real Go client, all alive
// at the same time.
//
// Why this job exists, stated plainly: the two implementations of this protocol have
// only ever been checked against a frozen artifact, never against each other. The Go
// suite runs a relay and Go clients with no browser; the web job runs a browser's
// worth of TypeScript with no relay and no Go toolchain; the docker job starts a
// relay and curls /health. No job has ever had a relay and a browser client in the
// same process space, and that gap is exactly the shape of the defects it hid — a
// Go slice marshalled as `null`, a status line that never moved, a link built from
// the wrong origin. All of them are invisible to a test that only ever sees one side.
//
// The Go participant is a plain `netherchat` CLI process, not a second browser. That
// is what makes this affordable: `tail` is a long-lived member that founds a room and
// prints what it decrypts, `send` is a transient member that joins and sends. Between
// them they cover both directions without a second browser context.
//
// The single most valuable assertion in this file is `page.on("pageerror")`. It knows
// nothing about any specific bug and fails the run on any uncaught page error, which
// is how it would have caught the `members: null` TypeError with no one having
// suspected it.

import { spawn, spawnSync, type ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect, type Page } from "@playwright/test";

const webDir = fileURLToPath(new URL("..", import.meta.url));
const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const exe = process.platform === "win32" ? ".exe" : "";

// Fixed, unusual ports with --strictPort: a collision fails loudly instead of
// silently moving the web server somewhere the relay proxy does not point.
const RELAY_PORT = Number(process.env.NC_LIVE_RELAY_PORT ?? 37301);
const WEB_PORT = Number(process.env.NC_LIVE_WEB_PORT ?? 37302);
const relayOrigin = `http://127.0.0.1:${RELAY_PORT}`;
const relayWS = `ws://127.0.0.1:${RELAY_PORT}`;
const webOrigin = `http://127.0.0.1:${WEB_PORT}`;

interface Bg {
  proc: ChildProcessByStdio<null, Readable, Readable>;
  out: string[];
  label: string;
}

const running: Bg[] = [];
let binDir = "";

function startBg(label: string, cmd: string, args: string[], opts: { cwd?: string; env?: Record<string, string> } = {}): Bg {
  const proc = spawn(cmd, args, {
    cwd: opts.cwd ?? repoRoot,
    env: { ...process.env, ...opts.env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const bg: Bg = { proc, out: [], label };
  const collect = (chunk: Buffer): void => {
    for (const line of chunk.toString("utf8").split("\n")) {
      if (line.trim()) bg.out.push(line.trim());
    }
  };
  proc.stdout.on("data", collect);
  proc.stderr.on("data", collect);
  running.push(bg);
  return bg;
}

function stopAll(): void {
  while (running.length) {
    const bg = running.pop()!;
    bg.proc.kill();
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Wait until url answers 2xx, or throw with whatever the process printed. */
async function waitForHTTP(url: string, bg: Bg, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const resp = await fetch(url);
      if (resp.ok) return;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) {
      throw new Error(`${bg.label} never answered ${url}\n${bg.out.join("\n")}`);
    }
    await sleep(200);
  }
}

/** Wait until one of bg's output lines contains needle. */
async function waitForLine(bg: Bg, needle: string, timeoutMs = 25_000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const hit = bg.out.find((l) => l.includes(needle));
    if (hit) return hit;
    if (Date.now() > deadline) {
      throw new Error(`${bg.label} never printed a line containing ${JSON.stringify(needle)}\n${bg.out.join("\n")}`);
    }
    await sleep(150);
  }
}

test.beforeAll(() => {
  binDir = mkdtempSync(join(tmpdir(), "nc-live-"));
  const build = spawnSync("go", ["build", "-o", binDir, "./cmd/netherchat-server", "./cmd/netherchat"], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (build.status !== 0) {
    throw new Error(`go build failed (${String(build.status)}):\n${build.stdout}\n${build.stderr}`);
  }
});

test.beforeAll(async () => {
  const relay = startBg("relay", join(binDir, "netherchat-server" + exe), ["--addr", `:${RELAY_PORT}`]);
  await waitForHTTP(`${relayOrigin}/health`, relay);

  // `vite dev` rather than `vite preview`: the dev server is what carries the /ws
  // proxy and the Origin rewrite the browser handshake needs (vite.config.ts
  // `server.proxy`). `preview` applies the clean-URL rewrites but has no proxy
  // config, so the built bundle cannot reach a relay through it today. That is a
  // real gap between this harness and the demo topology, and it is stated rather
  // than papered over: what runs here is the same modules, served differently.
  const viteBin = join(webDir, "node_modules", "vite", "bin", "vite.js");
  const web = startBg(
    "vite",
    process.execPath,
    [viteBin, "--port", String(WEB_PORT), "--strictPort", "--host", "127.0.0.1"],
    // cwd matters: run outside web/ and vite finds no config, no index.html, and no
    // proxy — it still prints "ready" and then 404s everything.
    { cwd: webDir, env: { NETHERCHAT_RELAY: relayOrigin } },
  );
  // Ask for the clean URL, so the cleanRoutes rewrite is on the tested path too.
  await waitForHTTP(`${webOrigin}/join?room=warmup`, web);
});

test.afterAll(() => {
  stopAll();
  // Best effort: on Windows the just-killed children can still hold the binaries.
  try {
    if (binDir) rmSync(binDir, { recursive: true, force: true });
  } catch {
    // leave the temp dir to the OS
  }
});

/**
 * Open the join page, take the display-name gate, and return the page plus its
 * uncaught-error log.
 *
 * The pageerror hook is the point of the whole harness. An exception thrown in a
 * WebSocket message listener does not close the socket or unregister the listener —
 * the browser reports it and carries on — so a client can be wedged, silent, and
 * still "connected" as far as every other assertion is concerned. This is the only
 * check that sees it, and it needs no knowledge of what went wrong.
 */
async function joinAs(page: Page, room: string, name: string): Promise<string[]> {
  const pageErrors: string[] = [];
  page.on("pageerror", (err) => pageErrors.push(err.message));

  await page.goto(`${webOrigin}/join?room=${room}`);
  await page.locator(".nc-gate input.nc-input").fill(name);
  await page.locator(".nc-gate button").click();
  await expect(page.locator(".nc-status")).toBeVisible();
  return pageErrors;
}

/** Fail with the page's own errors if any were raised. */
function assertNoPageErrors(pageErrors: string[]): void {
  expect(pageErrors, `uncaught page errors:\n${pageErrors.join("\n")}`).toEqual([]);
}

/**
 * Wait for the status pill to reach "encrypted", failing early on an uncaught page
 * error and, on timeout, naming the state it got stuck at.
 *
 * The ordering is the point. A plain `toBeVisible()` on the encrypted pill would
 * time out and report "element(s) not found", which says a symptom and hides the
 * cause; the page error is sitting right there saying exactly what broke. And when
 * there is no exception, the state the pill DID reach is the diagnosis — "connecting"
 * means no Welcome was ever processed, "waiting" means the room has no key holder.
 * Those are different bugs and the failure message should not conflate them.
 */
async function expectEncrypted(page: Page, pageErrors: string[], timeoutMs = 20_000): Promise<void> {
  const pill = page.locator('.nc-status[data-state="encrypted"]');
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (pageErrors.length > 0) assertNoPageErrors(pageErrors);
    if ((await pill.count()) > 0) return;
    if (Date.now() > deadline) {
      const state = await page.locator(".nc-status").getAttribute("data-state");
      const log = await page.locator(".nc-messages").textContent();
      throw new Error(
        `status never reached "encrypted"; it is ${JSON.stringify(state)}\ntranscript: ${String(log)}`,
      );
    }
    await sleep(150);
  }
}

async function browserSend(page: Page, text: string): Promise<void> {
  const composer = page.locator(".nc-composer input.nc-input");
  await expect(composer).toBeEnabled();
  await composer.fill(text);
  await page.locator(".nc-composer button").click();
}

function startTail(room: string, name: string): Bg {
  return startBg(
    `tail(${name})`,
    join(binDir, "netherchat" + exe),
    ["tail", room, "--server", relayWS, "--name", name],
  );
}

function goSend(room: string, name: string, text: string): void {
  // Flags BEFORE the message. `netherchat send <room> [flags] [message]` parses the
  // room as a positional and hands the rest to Go's flag package, which stops at the
  // first non-flag argument — put the message first and --server is silently ignored
  // in favour of its default.
  const res = spawnSync(join(binDir, "netherchat" + exe), ["send", room, "--server", relayWS, "--name", name, text], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (res.status !== 0) {
    throw new Error(`netherchat send failed (${String(res.status)}):\n${res.stdout}\n${res.stderr}`);
  }
}

// Ordering 1: the browser founds the room.
//
// This is the leg nothing has ever exercised, and it is two claims, not one. The
// browser must MINT epoch 0 when it arrives to an empty room — the path that a Go
// slice marshalled as `null` aborted five lines early. And it must then act as the
// DESIGNATED DISTRIBUTOR for every later joiner, wrapping the room key under
// nacl/box for a Go client it has never met. A Go client's key therefore comes from
// a browser here, which is the reverse of every other test in the repo.
test("browser founds the room, a Go client joins, messages cross both ways", async ({ page }) => {
  const room = "live-browser-first";
  const pageErrors = await joinAs(page, room, "web-guest");

  // Founding: no key can arrive from anywhere else, so reaching "encrypted" proves
  // the browser minted epoch 0 itself.
  await expectEncrypted(page, pageErrors);

  // The Go client joins second and can only get the key from the browser.
  const tail = startTail(room, "go-tail");

  // Browser → Go. The Go client decrypting this proves the browser-minted key
  // reached it and that both sides seal and open identically over a live wire.
  await browserSend(page, "from the browser");
  await waitForLine(tail, "from the browser");

  // Go → browser, a separate process joining a room it did not found.
  goSend(room, "go-sender", "from the terminal");
  await expect(page.locator(".nc-messages")).toContainText("from the terminal");

  assertNoPageErrors(pageErrors);
});

// Ordering 2: a Go client founds the room. The currently-working path, pinned so the
// fix to ordering 1 cannot regress it.
test("Go client founds the room, the browser joins, messages cross both ways", async ({ page }) => {
  const room = "live-tui-first";

  const tail = startTail(room, "go-tail");
  // The founder must be registered before the browser dials, or the browser wins
  // the race and this is ordering 1 again with a different name. The relay's own
  // room list is the authority on who is in the room.
  await expect
    .poll(async () => {
      const resp = await fetch(`${relayOrigin}/rooms`);
      const body = (await resp.json()) as { rooms: { name: string; members: number }[] };
      return body.rooms.find((r) => r.name === room)?.members ?? 0;
    })
    .toBe(1);

  const pageErrors = await joinAs(page, room, "web-guest");

  // The browser holds no key of its own here: reaching "encrypted" proves the Go
  // client wrapped epoch 0 for it and the browser unwrapped it.
  await expectEncrypted(page, pageErrors);

  await browserSend(page, "browser into a terminal-founded room");
  await waitForLine(tail, "browser into a terminal-founded room");

  goSend(room, "go-sender", "terminal into its own room");
  await expect(page.locator(".nc-messages")).toContainText("terminal into its own room");

  assertNoPageErrors(pageErrors);
});
