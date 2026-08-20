// The link-join client: someone opens /join?room=<room>&token=<token>, types a
// display name, and lands in an end-to-end encrypted room — no account, no
// localStorage, nothing persisted. A fresh ephemeral identity is generated for
// this visit only; closing the tab discards it. The crypto and wire protocol are
// byte-identical to the Go TUI (see ../crypto, ../net), so a browser guest and a
// terminal user share the same war room transparently.
//
// # D-J: CAN A BROWSER PARTICIPANT HOLD AN ATTESTED KEY? NO, AND IT IS STRUCTURAL
//
// An attestation binds a SUBJECT — the SHA-256 fingerprint of one Ed25519 public
// key — inside the issuer's signature. The key therefore has to exist before the
// issuer signs. This client calls newEphemeralIdentity() inside startChat, so
// the key is minted after the tab opens and no issuer can ever have seen it. A
// browser joiner is unattested BY CONSTRUCTION, not by omission, and the roster
// says so: no mark, and a tooltip reading "what the sender typed. It is not
// proven."
//
// Three ways it could hold one, and what each costs:
//
//  1. Persist a key per browser profile — a non-extractable WebCrypto key in
//     IndexedDB, enrolled once out of band — and store the attestation beside it.
//     Cost: "keys are generated fresh in your browser and never leave it, close
//     the tab and you're gone" stops being true, which is the headline promise of
//     the gate screen. It also makes a shared or kiosk browser a credential
//     holder with no OS keychain to put anything in, and this bundle is served by
//     the relay, so a compromised relay would gain reach over a key that today
//     dies with the tab.
//  2. Carry a credential in — the user supplies identity.json AND the matching
//     private key. Cost: the same loss of ephemerality, plus a long-lived private
//     key through a text field, and anyone who HAS a key file has a terminal.
//  3. Enrol live — the tab mints a key, shows its fingerprint, and an issuer
//     signs it during the session. Cost: an issuer service online and in the loop
//     at join time, which is the identity provider this whole design exists
//     without.
//
// Decided: none of them here. The link-join client stays unattested, and the
// absence is rendered rather than hidden. If an attested browser participant is
// ever needed it is option 1 in a DIFFERENT client, with the ephemerality promise
// explicitly withdrawn on that surface — not a flag added to this one.

import "../styles/tokens.css";
import "../styles/fonts.css";
import "./join.css";
import { NetherClient, type ClientEvent } from "../net/client";
import { pageRelay } from "../net/protocol";
import { newEphemeralIdentity } from "../crypto/identity";
import { identityDisplayFor, identityDisplayMark, identityDisplayLabel } from "../identity/attribution";

const app = document.getElementById("app")!;

const params = new URLSearchParams(location.search);
const room = (params.get("room") ?? "").trim();
const token = (params.get("token") ?? "").trim();

// The relay is the origin that served this page — a link carries the room and the
// token, never the endpoint. See pageRelay() for why the link is not allowed a say.
const relay = pageRelay();

if (!room) {
  renderError("This link is missing its room.", "Ask whoever sent it for a fresh invite link.");
} else {
  renderGate(room);
}

// --- screens ----------------------------------------------------------------

function renderGate(roomName: string): void {
  app.replaceChildren();

  const card = div("nc-gate");
  card.appendChild(brand());

  const h1 = document.createElement("h1");
  h1.append("join ");
  h1.appendChild(span("nc-room", "#" + roomName));
  card.appendChild(h1);

  card.appendChild(p("nc-sub", "An end-to-end encrypted room. Ephemeral — nothing is saved."));

  // Named before the user commits: this is the last screen on which they can
  // simply close the tab. The full ws URL rather than the bare host — there is
  // room for it here, and the scheme says whether the transport is protected.
  card.appendChild(relayLine(relay.url));

  const form = document.createElement("form");
  form.className = "nc-form";
  const input = document.createElement("input");
  input.className = "nc-input";
  input.placeholder = "display name";
  input.maxLength = 48;
  input.autocomplete = "off";
  input.autofocus = true;
  const btn = document.createElement("button");
  btn.className = "nc-btn";
  btn.type = "submit";
  btn.textContent = "Join room";
  form.append(input, btn);

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const name = input.value.trim() || "guest";
    startChat(roomName, name);
  });
  card.appendChild(form);

  card.appendChild(
    p("nc-fine", "No account. Keys are generated fresh in your browser and never leave it. Close the tab and you're gone."),
  );

  app.appendChild(card);
  input.focus();
}

function renderError(title: string, sub: string): void {
  app.replaceChildren();
  const box = div("nc-error");
  box.appendChild(brand());
  const h1 = document.createElement("h1");
  h1.textContent = title;
  box.appendChild(h1);
  box.appendChild(p("", sub));
  app.appendChild(box);
}

/**
 * The "relay <endpoint>" row shown on both screens. `text` is what is displayed
 * (the full ws URL where there is room for it, the bare host in the chat header);
 * the complete URL always goes to the tooltip and the accessible name, so the
 * scheme is never hidden from someone who cannot hover. Text only — no innerHTML.
 */
function relayLine(text: string, fullURL: string = text): HTMLElement {
  const row = div("nc-relay");
  row.append("relay ");
  row.appendChild(span("nc-relay-host", text));
  row.title = fullURL;
  row.setAttribute("role", "note");
  row.setAttribute("aria-label", "relay " + fullURL);
  return row;
}

/**
 * How long to wait for a room key before saying so.
 *
 * There is no timer anywhere else in this client, and the absence was the whole
 * problem: `connecting…` was set once at render and cleared by exactly two events,
 * so every failure to establish a key — the relay never answering, a distributor
 * that holds no key, an exception in the Welcome handler — presented as the same
 * indefinite "connecting…". Fifteen seconds is well past a healthy key exchange
 * (one round trip through the relay to the oldest member and back) and well inside
 * the patience of someone who was told to click a link and start talking.
 */
const KEY_DEADLINE_MS = 15_000;

/**
 * What to do when no key arrives. Specific, because the remedy is specific: a room
 * whose key holders have all gone cannot re-mint one — minting is gated on being
 * first into an empty room, and the room is not empty. Tearing it down and rejoining
 * is the recovery, and today only a terminal client can do the tearing down.
 */
const NO_KEY_ADVICE =
  "no room key after 15s — nobody in this room can hand one out. " +
  "Ask a terminal client to run /scuttle and then rejoin, " +
  "or open the room from a terminal client first.";

function startChat(roomName: string, name: string): void {
  const ui = renderChat(roomName);
  ui.selfName = name;
  renderRoster(ui); // "just you", before the socket has said anything

  const client = new NetherClient(
    relay.url,
    roomName,
    name,
    newEphemeralIdentity(),
    (e) => onEvent(ui, e),
    token,
  );

  ui.form.addEventListener("submit", (e) => {
    e.preventDefault();
    const text = ui.input.value.trim();
    if (!text) return;
    try {
      client.send(text);
      ui.input.value = "";
    } catch (err) {
      addLine(ui, "nc-err", "could not send: " + String(err));
    }
  });

  // Best-effort clean exit so the room's member count updates promptly.
  window.addEventListener("pagehide", () => {
    clearKeyDeadline(ui);
    client.close();
  });

  client.connect();

  // Armed after connect(), cleared by keyReady, by a disconnect, or by an
  // unprocessable frame — whichever gets there first. Nothing else in this client
  // can move the status line off "connecting…" when the key simply never comes.
  ui.keyTimer = window.setTimeout(() => {
    ui.keyTimer = undefined;
    if (ui.status.dataset.state === "encrypted") return;
    setStatus(ui, "error", "no room key");
    addLine(ui, "nc-err", NO_KEY_ADVICE);
  }, KEY_DEADLINE_MS);
}

function clearKeyDeadline(ui: ChatUI): void {
  if (ui.keyTimer !== undefined) {
    window.clearTimeout(ui.keyTimer);
    ui.keyTimer = undefined;
  }
}

/** One person in the roster, as this page knows them. */
interface RosterEntry {
  id: string;
  name: string;
  /** SSH SHA-256 fingerprint of their identity key: the value an attestation's
   * `subject` names, so the roster can ask whether a credential is about the key
   * it arrived on. Empty for you, whose key is not on the wire from anyone. */
  fingerprint: string;
  /** base64 of their identity artifact, or undefined. Never verified here. */
  attestation?: string;
}

interface ChatUI {
  form: HTMLFormElement;
  input: HTMLInputElement;
  messages: HTMLElement;
  status: HTMLElement;
  statusText: HTMLElement;
  count: HTMLElement;
  /** The named roster (D-I), in join order, excluding you. */
  roster: HTMLElement;
  people: RosterEntry[];
  selfName: string;
  members: number;
  /** Whether the one-time "what unsigned means" note has been shown. */
  explainedUnsigned: boolean;
  /** Pending key-arrival deadline, if one is armed. */
  keyTimer?: number;
}

function renderChat(roomName: string): ChatUI {
  app.replaceChildren();
  const chat = div("nc-chat");

  const head = div("nc-head");
  head.appendChild(span("nc-title", "#" + roomName));
  // The status line says the room is encrypted; this says who it is encrypted
  // WITH. Someone who cannot see the endpoint cannot notice it is the wrong one.
  head.appendChild(relayLine(relay.host, relay.url));
  head.appendChild(div("nc-spacer"));

  const status = div("nc-status");
  status.dataset.state = "connecting";
  status.appendChild(div("nc-dot"));
  const statusText = span("", "connecting…");
  status.appendChild(statusText);
  head.appendChild(status);

  const count = span("nc-count", "");
  head.appendChild(count);
  chat.appendChild(head);

  // The roster. Before this the header said "3 here" and nothing else — a count
  // with no names, which is the same gap /roster --signed has in the TUI. It is
  // its own strip rather than a sidebar because this client is one column on a
  // phone as often as not.
  const roster = div("nc-roster");
  roster.setAttribute("role", "list");
  roster.setAttribute("aria-label", "people in this room");
  chat.appendChild(roster);

  const messages = div("nc-messages");
  chat.appendChild(messages);

  const form = document.createElement("form");
  form.className = "nc-composer";
  const input = document.createElement("input");
  input.className = "nc-input";
  input.placeholder = "message #" + roomName;
  input.autocomplete = "off";
  input.disabled = true;
  const send = document.createElement("button");
  send.className = "nc-btn";
  send.type = "submit";
  send.textContent = "send";
  send.disabled = true;
  form.append(input, send);
  chat.appendChild(form);

  app.appendChild(chat);

  return {
    form, input, messages, status, statusText, count, roster,
    people: [], selfName: "", members: 0, explainedUnsigned: false,
  };
}

/**
 * Redraw the roster. D-I, in a browser (web/src/identity/attribution.ts):
 *
 *   - the name drawn is `entry.name`, the name the sender chose, because this
 *     page cannot check any other one. It holds no issuer key, has no way to be
 *     given one, and a credential's own display_name is a string a sender put
 *     in a JSON object.
 *   - a peer carrying a credential gets ◇ — a claim arrived and nobody checked
 *     it — never ✓ and never ◆.
 *   - the claim itself is in the tooltip and the accessible name, so a glyph is
 *     never the only carrier of the meaning.
 *
 * Every string here goes through textContent or a property assignment. Names,
 * principals and issuer fingerprints are all attacker-influenced.
 */
function renderRoster(ui: ChatUI): void {
  ui.roster.replaceChildren();
  const entries: RosterEntry[] = [{ id: "", name: ui.selfName, fingerprint: "" }, ...ui.people];
  for (const e of entries) {
    const chip = div("nc-person");
    chip.setAttribute("role", "listitem");

    // The decision FIRST, and the name comes out of it. Drawing e.name and then
    // asking the decision only for a mark would give the right answer today by
    // coincidence — identityDisplayFor cannot reach a verified state here, so
    // display.name is always e.name — and the wrong one on the day a surface can
    // verify. It also makes the guard vacuous: a version of this file that
    // promoted an unchecked display_name passed the live browser test, because
    // nothing on screen was reading the decision's name at all.
    const display = identityDisplayFor(e.name, e.fingerprint, e.attestation);
    const label = span("nc-person-name", display.name);
    label.style.color = nameColor(display.name);
    chip.appendChild(label);
    if (e.id === "") {
      chip.appendChild(span("nc-person-you", " (you)"));
    }
    const mark = identityDisplayMark(display.state);
    if (mark) {
      const glyph = span("nc-person-mark", mark);
      glyph.title = identityDisplayLabel(display);
      glyph.setAttribute("aria-label", identityDisplayLabel(display));
      chip.appendChild(glyph);
    } else {
      chip.title = identityDisplayLabel(display);
    }
    ui.roster.appendChild(chip);
  }
  setMembers(ui, entries.length);
}

// --- event handling ---------------------------------------------------------

function onEvent(ui: ChatUI, e: ClientEvent): void {
  switch (e.t) {
    case "connected":
      ui.people = e.members.map((m) => ({ id: m.id, name: m.name, fingerprint: m.fingerprint, attestation: m.attestation }));
      renderRoster(ui);
      // In the room, no key yet. This state is the one the client was missing, and
      // its absence is what made two different defects look identical on screen: a
      // Welcome that threw before emitting anything left the pill at "connecting…",
      // and a room whose key holders had all gone emitted `connected` and then
      // nothing — also leaving the pill at "connecting…". They are now
      // distinguishable at a glance. The TUI has had this state all along
      // ("connected (awaiting key)", tui/ui/app/model.go).
      if (ui.status.dataset.state !== "encrypted") {
        setStatus(ui, "waiting", "connected — waiting for the room key");
      }
      break;
    case "keyReady":
      clearKeyDeadline(ui);
      setStatus(ui, "encrypted", "end-to-end encrypted");
      ui.input.disabled = false;
      (ui.form.querySelector("button") as HTMLButtonElement).disabled = false;
      ui.input.focus();
      break;
    case "message":
      addMessage(ui, e.self ? "you" : e.fromName, e.text, e.self, e.signed, e.at);
      break;
    case "serverMessage":
      addPlain(ui, e.from, e.text);
      break;
    case "control":
      if (e.action === "vanish") {
        ui.messages.replaceChildren();
        addLine(ui, "nc-sys", `${e.self ? "you" : e.byName ?? "someone"} vanished the room — history cleared, key rotated`);
      } else if (e.action === "ttl") {
        addLine(ui, "nc-sys", e.ttlSeconds && e.ttlSeconds > 0 ? `message ttl set to ${e.ttlSeconds}s` : "message ttl disabled");
      }
      break;
    case "memberJoined":
      ui.people = [...ui.people, { id: e.id, name: e.name, fingerprint: e.fingerprint, attestation: e.attestation }];
      renderRoster(ui);
      addLine(ui, "nc-sys", `${e.name} joined`);
      break;
    case "memberLeft":
      ui.people = ui.people.filter((m) => m.id !== e.id);
      renderRoster(ui);
      addLine(ui, "nc-sys", `${e.name} left`);
      break;
    case "error":
      addLine(ui, "nc-err", friendlyError(e.message));
      // An error has to move the status line at least once, because the transcript
      // is not where someone looks when nothing is happening. Two cases qualify: a
      // frame the client could not process at all (`fatal` — its state is now
      // unknown, whatever the connection looks like), and any error at all while
      // the key has not arrived, where the pill would otherwise sit at
      // "connecting…" or "waiting" until the deadline. An error AFTER the key is a
      // per-message problem in a room that demonstrably works, and turning the pill
      // red there would make it lie about the connection.
      if (e.fatal || ui.status.dataset.state === "connecting" || ui.status.dataset.state === "waiting") {
        clearKeyDeadline(ui);
        setStatus(ui, "error", e.fatal ? "protocol error" : "could not join");
      }
      break;
    case "disconnected":
      clearKeyDeadline(ui);
      setStatus(ui, "down", "disconnected");
      ui.input.disabled = true;
      (ui.form.querySelector("button") as HTMLButtonElement).disabled = true;
      break;
    // execResult / invite are not surfaced in the join client.
  }
}

/**
 * The five connection states, and the whole of what this client says about itself:
 *
 *   connecting  socket open pending, no Welcome yet
 *   waiting     in the room, no room key yet
 *   encrypted   the key arrived; the composer is live
 *   error       no key by the deadline, or a frame that could not be processed
 *   down        the socket closed
 *
 * `connecting` and `waiting` are both "not usable yet" but have different causes and
 * different remedies, which is why they are separate; `error` and `down` are both
 * terminal but only one of them means the connection is gone.
 */
type Status = "connecting" | "waiting" | "encrypted" | "error" | "down";

function setStatus(ui: ChatUI, state: Status, label: string): void {
  ui.status.dataset.state = state;
  ui.statusText.textContent = label;
}

function setMembers(ui: ChatUI, n: number): void {
  ui.members = n;
  ui.count.textContent = n === 1 ? "just you" : `${n} here`;
}

function friendlyError(message: string): string {
  if (message.includes("invite")) {
    return "This link has expired or was already used. Ask for a fresh invite link.";
  }
  return message;
}

// --- message rendering (all user text via textContent — no innerHTML) -------

// The signed baseline is deliberately unmarked (a chip on every line would be
// noise), so the unsigned case must carry the whole signal on its own: a word
// rather than a symbol, warn colour, a tinted row with a left rule, a hover/focus
// explanation, and a one-time note the first time it happens that also states
// what the *absence* of a mark means. Someone who has never heard of message
// signing should still read "unsigned … not verified" and understand it.
const UNSIGNED_TITLE =
  "Unsigned: this message carried no signature, so it is attributed to the sender " +
  "by the relay's routing alone — not proven. It is still end-to-end encrypted; " +
  "the relay cannot read or alter the text, but it can strip a signature.";

const UNSIGNED_NOTE =
  "⚠ the message below arrived unsigned — its sender is claimed, not proven. " +
  "A relay can strip a signature, and older clients never send one. Messages " +
  "without this mark were signature-verified.";

function addMessage(
  ui: ChatUI,
  name: string,
  text: string,
  self: boolean,
  signed: boolean,
  atMs: number,
): void {
  if (!signed && !ui.explainedUnsigned) {
    ui.explainedUnsigned = true;
    addLine(ui, "nc-unsigned-note", UNSIGNED_NOTE);
  }

  const row = div("nc-row");
  if (self) row.classList.add("nc-self");
  if (!signed) row.classList.add("nc-unsigned-row");
  row.appendChild(span("nc-ts", fmtTime(atMs)));
  const nameEl = span("nc-name", name);
  if (!self) nameEl.style.color = nameColor(name);
  row.appendChild(nameEl);
  if (!signed) row.appendChild(unsignedBadge());
  row.append(": ");
  const textEl = span("nc-text", "");
  appendRichText(textEl, text);
  row.appendChild(textEl);
  push(ui, row);
}

/** The badge drawn after an unsigned sender's name. Text only — no innerHTML. */
function unsignedBadge(): HTMLElement {
  const badge = span("nc-unsigned", "⚠ unsigned");
  badge.title = UNSIGNED_TITLE;
  // Reachable without a pointer: keyboard focus and screen readers both get the
  // long explanation, which a hover-only tooltip would hide on touch devices.
  badge.tabIndex = 0;
  badge.setAttribute("role", "note");
  badge.setAttribute("aria-label", UNSIGNED_TITLE);
  return badge;
}

function addPlain(ui: ChatUI, from: string, text: string): void {
  const row = div("nc-row nc-plain");
  row.appendChild(span("nc-tag", `⚙ ${from} (plaintext) `));
  row.appendChild(document.createTextNode(text));
  push(ui, row);
}

function addLine(ui: ChatUI, cls: string, text: string): void {
  const row = div("nc-row " + cls);
  row.textContent = text;
  push(ui, row);
}

function push(ui: ChatUI, row: HTMLElement): void {
  const atBottom = ui.messages.scrollHeight - ui.messages.scrollTop - ui.messages.clientHeight < 40;
  ui.messages.appendChild(row);
  if (atBottom) ui.messages.scrollTop = ui.messages.scrollHeight;
}

/** Render `code` spans inline; everything else is plain (escaped) text. */
function appendRichText(parent: HTMLElement, text: string): void {
  const parts = text.split("`");
  parts.forEach((part, i) => {
    if (i % 2 === 1 && i < parts.length - 1) {
      const code = document.createElement("code");
      code.textContent = part;
      parent.appendChild(code);
    } else if (part) {
      // Re-add backticks that were not part of a matched pair.
      const prefix = i % 2 === 1 ? "`" : "";
      parent.appendChild(document.createTextNode(prefix + part));
    }
  });
}

// --- small DOM + format helpers ---------------------------------------------

function div(className: string): HTMLElement {
  const e = document.createElement("div");
  e.className = className;
  return e;
}

function span(className: string, text: string): HTMLElement {
  const e = document.createElement("span");
  if (className) e.className = className;
  if (text) e.textContent = text;
  return e;
}

function p(className: string, text: string): HTMLElement {
  const e = document.createElement("p");
  if (className) e.className = className;
  e.textContent = text;
  return e;
}

function brand(): HTMLElement {
  const wrap = div("nc-glyph");
  // Static markup (no user data) — safe to set as innerHTML. The literal below is
  // fixed at build time: no interpolation, no argument, nothing off the wire reaches
  // it. Every string that IS attacker-influenced goes through textContent instead,
  // which is what the rule is here to keep true.
  // eslint-disable-next-line no-restricted-syntax
  wrap.innerHTML =
    `<svg width="22" height="22" viewBox="0 0 32 32" fill="none" aria-hidden="true">` +
    `<g stroke="var(--accent)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">` +
    `<path d="M8 25 L8 9" /><path d="M8 9 L24 23" /><path d="M24 23 L24 7" /></g>` +
    `<g fill="var(--accent)"><circle cx="8" cy="25.2" r="1.9" /><circle cx="24" cy="6.8" r="1.9" /></g></svg>`;
  wrap.append("netherchat");
  return wrap;
}

const NAME_COLORS = ["#a78bfa", "#7c3aed", "#c4b5fd", "#8b5cf6", "#d8b4fe", "#9d7cff"];

function nameColor(name: string): string {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return NAME_COLORS[h % NAME_COLORS.length];
}

function fmtTime(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
