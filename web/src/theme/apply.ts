// Applies a Theme to the document as CSS custom properties. Switching is instant:
// set the variables, and every rule keyed off them re-paints on the next frame —
// no reload, mirroring the TUI's hot theme swap (R2).

import { defaultTheme, getTheme, type Theme } from "./themes";

const STORAGE_KEY = "netherchat.theme";

// System font fallbacks layered behind each theme's preferred font, so the UI is
// always legible even before the (optional, self-hosted) brand fonts load.
const MONO_FALLBACK =
  '"JetBrains Mono", "SF Mono", "Cascadia Code", "Fira Code", ui-monospace, Menlo, Consolas, monospace';
const UI_FALLBACK = '"Space Grotesk", "Inter", ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif';

export function applyTheme(theme: Theme): void {
  const r = document.documentElement;
  r.style.setProperty("--bg", theme.bg);
  r.style.setProperty("--text", theme.text);
  r.style.setProperty("--muted", theme.muted);
  r.style.setProperty("--accent", theme.accent);
  r.style.setProperty("--accent2", theme.accent2);
  r.style.setProperty("--success", theme.success);
  r.style.setProperty("--warn", theme.warn);
  r.style.setProperty("--error", theme.error);
  r.style.setProperty("--font-mono", `"${theme.font}", ${MONO_FALLBACK}`);
  r.style.setProperty("--font-ui", UI_FALLBACK);
  r.setAttribute("data-theme", theme.name);
}

export function loadThemeName(): string {
  return localStorage.getItem(STORAGE_KEY) ?? defaultTheme().name;
}

export function saveThemeName(name: string): void {
  localStorage.setItem(STORAGE_KEY, name);
}

/** Apply the persisted theme (or the brand default). Call once at startup. */
export function initTheme(): Theme {
  const theme = getTheme(loadThemeName()) ?? defaultTheme();
  applyTheme(theme);
  return theme;
}

/**
 * Stable per-user colour from a theme's palette — FNV-1a (32-bit) of the name
 * modulo the palette size, identical to theme.go's UserColor so a given name
 * gets the same colour in the TUI and the web client.
 */
export function userColor(theme: Theme, name: string): string {
  if (theme.users.length === 0) return theme.accent2;
  return theme.users[fnv32a(name) % theme.users.length];
}

function fnv32a(s: string): number {
  let h = 0x811c9dc5; // offset basis
  const bytes = new TextEncoder().encode(s);
  for (const b of bytes) {
    h ^= b;
    h = Math.imul(h, 0x01000193) >>> 0; // * FNV prime, mod 2^32
  }
  return h >>> 0;
}
