// The Status Beacon reader (§1.2): someone opens
// /beacon?room=<room>#key=<base64 beacon key>, and this page fetches the room's
// beacon ciphertext from the relay and decrypts it IN THE BROWSER with the key from
// the link. It is strictly READ-ONLY — there is no message list, no join button, no
// room membership. The beacon key reads the status and NOTHING else: it cannot
// decrypt room messages, which use a different key.
//
// The key rides in the FRAGMENT so it is never sent to the relay — not in the page
// request line, and not in the `Referer` of the 30s poll below. See link.ts for the
// full reasoning and for why a `?key=` link is refused rather than honoured.
//
// It auto-refreshes every 30s, so a stakeholder watching the link sees status
// updates without reloading. Nothing is persisted.

import { fromB64 } from "../crypto/base64";
import { openBeacon } from "../crypto/beacon";
import { parseBeaconLink, linkProblem } from "./link";

const REFRESH_MS = 30_000;

const app = document.getElementById("app")!;
const link = parseBeaconLink(location.search, location.hash);

// Declared for the closures below; only ever read on the ok path.
const room = link.ok ? link.room : "";
const beaconKey = link.ok ? link.key : null;

if (!link.ok) {
  const [headline, detail] = linkProblem(link.problem);
  renderCard("muted", headline, detail);
} else {
  renderCard("muted", "Loading status…", "");
  void refresh();
  window.setInterval(() => void refresh(), REFRESH_MS);
}

async function refresh(): Promise<void> {
  try {
    const resp = await fetch(`/beacon/${encodeURIComponent(room)}`, { cache: "no-store" });
    if (resp.status === 404) {
      renderCard("muted", "No status set.", "");
      return;
    }
    if (!resp.ok) {
      renderCard("muted", "Could not load the status.", `Server returned ${resp.status}.`);
      return;
    }
    const body = (await resp.json()) as { ciphertext: string; updated_at: string };
    const text = openBeacon(beaconKey!, fromB64(body.ciphertext));
    renderCard("status", text, "updated " + formatUpdated(body.updated_at));
  } catch (e) {
    renderCard("muted", "Could not decrypt the status.", String(e instanceof Error ? e.message : e));
  }
}

// renderCard draws the single status card. kind "status" is the live status line;
// "muted" is a placeholder/error state.
function renderCard(kind: "status" | "muted", text: string, meta: string): void {
  app.replaceChildren();

  const card = el("div", "nc-card");

  const eyebrow = el("div", "nc-eyebrow");
  eyebrow.appendChild(el("span", "nc-dot"));
  eyebrow.append(room ? `status · #${room}` : "status");
  card.appendChild(eyebrow);

  const status = el("p", kind === "status" ? "nc-status" : "nc-status muted");
  status.textContent = text;
  card.appendChild(status);

  if (meta) {
    const m = el("div", "nc-meta");
    m.textContent = meta;
    card.appendChild(m);
  }

  const foot = el("div", "nc-foot");
  const b = document.createElement("b");
  b.textContent = "Netherchat";
  foot.append(b, " — messaging that lives below the surface");
  card.appendChild(foot);

  app.appendChild(card);
}

function formatUpdated(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function el(tag: string, className: string): HTMLElement {
  const e = document.createElement(tag);
  e.className = className;
  return e;
}
