// Landing-page interactions: theme picker (shared with the app — same palettes,
// same persisted choice), a clickable theme strip, copy-to-clipboard buttons, and
// the footer year. No frameworks, no outbound calls.

import "../styles/tokens.css";
import "../styles/fonts.css";
import "./landing.css";
import { THEMES } from "../theme/themes";
import { applyTheme, saveThemeName, initTheme } from "../theme/apply";

initTheme();

function currentName(): string {
  return document.documentElement.getAttribute("data-theme") ?? THEMES[0].name;
}

function setTheme(name: string): void {
  const t = THEMES.find((x) => x.name === name) ?? THEMES[0];
  applyTheme(t);
  saveThemeName(t.name);
  refresh();
}

function swatchHTML(name: string): string {
  const t = THEMES.find((x) => x.name === name) ?? THEMES[0];
  return (
    `<span class="lp-swatch" style="background:${t.bg}">` +
    `<i style="background:${t.accent}"></i><i style="background:${t.accent2}"></i><i style="background:${t.success}"></i>` +
    `</span>`
  );
}

// --- nav dropdown -----------------------------------------------------------

const picker = document.querySelector<HTMLElement>("[data-themepicker]");
let pickerOpen = false;

function buildPicker(root: HTMLElement): void {
  root.innerHTML =
    `<button type="button" class="lp-themepicker-btn">${swatchHTML(currentName())}` +
    `<span class="lp-themepicker-name">${currentName()}</span></button>` +
    `<ul class="lp-themepicker-list" hidden>` +
    THEMES.map(
      (t) => `<li><button type="button" data-name="${t.name}">${swatchHTML(t.name)}<span>${t.name}</span></button></li>`,
    ).join("") +
    `</ul>`;

  const btn = root.querySelector<HTMLButtonElement>(".lp-themepicker-btn")!;
  const list = root.querySelector<HTMLUListElement>(".lp-themepicker-list")!;

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    pickerOpen = !pickerOpen;
    list.hidden = !pickerOpen;
  });
  list.querySelectorAll<HTMLButtonElement>("button[data-name]").forEach((b) => {
    b.addEventListener("click", () => {
      setTheme(b.dataset.name!);
      pickerOpen = false;
      list.hidden = true;
    });
  });
  document.addEventListener("click", () => {
    if (pickerOpen) {
      pickerOpen = false;
      list.hidden = true;
    }
  });
}

// --- theme strip ------------------------------------------------------------

const strip = document.querySelector<HTMLElement>("[data-theme-strip]");

function buildStrip(root: HTMLElement): void {
  root.innerHTML = THEMES.map(
    (t) =>
      `<button type="button" class="lp-theme-card" data-name="${t.name}" style="background:${t.bg};color:${t.text}">` +
      `<span class="lp-theme-dots"><i style="background:${t.accent}"></i><i style="background:${t.accent2}"></i>` +
      `<i style="background:${t.success}"></i><i style="background:${t.warn}"></i></span>` +
      `<span class="lp-theme-name" style="color:${t.muted}">${t.name}</span></button>`,
  ).join("");
  root.querySelectorAll<HTMLButtonElement>(".lp-theme-card").forEach((b) => {
    b.addEventListener("click", () => setTheme(b.dataset.name!));
  });
}

function refresh(): void {
  if (picker) {
    const nameEl = picker.querySelector(".lp-themepicker-name");
    const sw = picker.querySelector(".lp-swatch");
    if (nameEl) nameEl.textContent = currentName();
    if (sw) sw.outerHTML = swatchHTML(currentName());
  }
  document.querySelectorAll<HTMLButtonElement>(".lp-theme-card").forEach((b) => {
    b.classList.toggle("is-active", b.dataset.name === currentName());
  });
}

if (picker) buildPicker(picker);
if (strip) buildStrip(strip);
refresh();

// --- copy buttons + year ----------------------------------------------------

document.querySelectorAll<HTMLButtonElement>(".lp-copy").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const text = btn.getAttribute("data-copy") ?? "";
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* clipboard blocked — ignore */
    }
    const prev = btn.textContent;
    btn.textContent = "copied";
    btn.classList.add("is-copied");
    window.setTimeout(() => {
      btn.textContent = prev;
      btn.classList.remove("is-copied");
    }, 1200);
  });
});

const yearEl = document.querySelector("[data-year]");
if (yearEl) yearEl.textContent = String(new Date().getFullYear());
