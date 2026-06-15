// The link-join client: someone opens /join?room=<room>&token=<token>, types a
// display name, and lands in an end-to-end encrypted room — no account, no
// localStorage, nothing persisted. A fresh ephemeral identity is generated for
// this visit only; closing the tab discards it. The crypto and wire protocol are
// byte-identical to the Go TUI (see ../crypto, ../net), so a browser guest and a
// terminal user share the same war room transparently.

import "../styles/tokens.css";
import "../styles/fonts.css";
import "./join.css";
import { NetherClient, type ClientEvent } from "../net/client";
import { defaultWsUrl, normalizeWsUrl } from "../net/protocol";
import { newEphemeralIdentity } from "../crypto/identity";

const app = document.getElementById("app")!;

const params = new URLSearchParams(location.search);
const room = (params.get("room") ?? "").trim();
const token = (params.get("token") ?? "").trim();

// An invite link may pin the relay with `?server=…` (e.g. a self-hosted box at
// an arbitrary IP); without it we default to the origin that served this page.
const serverParam = (params.get("server") ?? "").trim();
const wsUrl = serverParam ? normalizeWsUrl(serverParam) : defaultWsUrl();

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

function startChat(roomName: string, name: string): void {
  const ui = renderChat(roomName);

  const client = new NetherClient(
    wsUrl,
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
  window.addEventListener("pagehide", () => client.close());

  client.connect();
}

interface ChatUI {
  form: HTMLFormElement;
  input: HTMLInputElement;
  messages: HTMLElement;
  status: HTMLElement;
  statusText: HTMLElement;
  count: HTMLElement;
  members: number;
}

function renderChat(roomName: string): ChatUI {
  app.replaceChildren();
  const chat = div("nc-chat");

  const head = div("nc-head");
  head.appendChild(span("nc-title", "#" + roomName));
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

  return { form, input, messages, status, statusText, count, members: 0 };
}

// --- event handling ---------------------------------------------------------

function onEvent(ui: ChatUI, e: ClientEvent): void {
  switch (e.t) {
    case "connected":
      setMembers(ui, e.members.length + 1);
      break;
    case "keyReady":
      setStatus(ui, "encrypted", "end-to-end encrypted");
      ui.input.disabled = false;
      (ui.form.querySelector("button") as HTMLButtonElement).disabled = false;
      ui.input.focus();
      break;
    case "message":
      addMessage(ui, e.self ? "you" : e.fromName, e.text, e.self, e.at);
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
      setMembers(ui, ui.members + 1);
      addLine(ui, "nc-sys", `${e.name} joined`);
      break;
    case "memberLeft":
      setMembers(ui, Math.max(0, ui.members - 1));
      addLine(ui, "nc-sys", `${e.name} left`);
      break;
    case "error":
      addLine(ui, "nc-err", friendlyError(e.message));
      break;
    case "disconnected":
      setStatus(ui, "down", "disconnected");
      ui.input.disabled = true;
      (ui.form.querySelector("button") as HTMLButtonElement).disabled = true;
      break;
    // execResult / invite are not surfaced in the join client.
  }
}

function setStatus(ui: ChatUI, state: "connecting" | "encrypted" | "down", label: string): void {
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

function addMessage(ui: ChatUI, name: string, text: string, self: boolean, atMs: number): void {
  const row = div("nc-row");
  if (self) row.classList.add("nc-self");
  row.appendChild(span("nc-ts", fmtTime(atMs)));
  const nameEl = span("nc-name", name);
  if (!self) nameEl.style.color = nameColor(name);
  row.appendChild(nameEl);
  row.append(": ");
  const textEl = span("nc-text", "");
  appendRichText(textEl, text);
  row.appendChild(textEl);
  push(ui, row);
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
  // Static markup (no user data) — safe to set as innerHTML.
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
