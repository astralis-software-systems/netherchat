// The eight named Netherchat themes, transcribed verbatim from the TUI's
// tui/ui/theme/theme.go so the web client and terminal client look identical.
// `nether` is the default (the brand palette). Per-theme fonts are honoured here
// for real (R3 / ARCHITECTURE_DECISION.md §8.1) — the web client controls CSS,
// so unlike the TUI it can actually switch fonts.

export interface Theme {
  name: string;
  font: string; // primary mono font for this theme
  bg: string;
  text: string;
  muted: string;
  accent: string;
  accent2: string;
  success: string;
  warn: string;
  error: string;
  rainbow: boolean;
  users: string[]; // palette usernames are coloured from
}

export const THEMES: Theme[] = [
  {
    name: "nether",
    font: "JetBrains Mono",
    bg: "#0a0a12", text: "#e2e0f0", muted: "#7c6fa0",
    accent: "#7c3aed", accent2: "#a78bfa",
    success: "#8be9a8", warn: "#f0c674", error: "#ff6b6b",
    rainbow: false,
    users: ["#a78bfa", "#7c3aed", "#c4b5fd", "#8b5cf6", "#d8b4fe", "#9d7cff"],
  },
  {
    name: "abyss",
    font: "JetBrains Mono",
    bg: "#04080a", text: "#d0f0f5", muted: "#4a6b78",
    accent: "#22d3ee", accent2: "#67e8f9",
    success: "#5eead4", warn: "#fcd34d", error: "#fb7185",
    rainbow: false,
    users: ["#22d3ee", "#67e8f9", "#7dd3fc", "#38bdf8", "#5eead4", "#a5f3fc"],
  },
  {
    name: "ember",
    font: "JetBrains Mono",
    bg: "#0f0a06", text: "#f5e6d8", muted: "#9a6b4a",
    accent: "#fb923c", accent2: "#fdba74",
    success: "#bef264", warn: "#fcd34d", error: "#f87171",
    rainbow: false,
    users: ["#fb923c", "#fdba74", "#f59e0b", "#fbbf24", "#fca5a5", "#fed7aa"],
  },
  {
    name: "ghost",
    font: "IBM Plex Mono",
    bg: "#0a0a0a", text: "#d0d0d0", muted: "#707070",
    accent: "#e8e8e8", accent2: "#b0b0b0",
    success: "#c0c0c0", warn: "#a0a0a0", error: "#f0f0f0",
    rainbow: false,
    users: ["#d0d0d0", "#a8a8a8", "#bcbcbc", "#909090", "#e0e0e0", "#808080"],
  },
  {
    name: "sprinkles",
    font: "Fira Code",
    bg: "#0a0a12", text: "#f5f5fa", muted: "#8a8aa0",
    accent: "#ff79c6", accent2: "#8be9fd",
    success: "#50fa7b", warn: "#f1fa8c", error: "#ff5555",
    rainbow: true,
    users: [
      "#ff5555", "#ffb86c", "#f1fa8c", "#50fa7b", "#8be9fd",
      "#bd93f9", "#ff79c6", "#ff6e6e", "#69ff94", "#d6acff",
    ],
  },
  {
    name: "dracula",
    font: "JetBrains Mono",
    bg: "#282a36", text: "#f8f8f2", muted: "#6272a4",
    accent: "#bd93f9", accent2: "#ff79c6",
    success: "#50fa7b", warn: "#f1fa8c", error: "#ff5555",
    rainbow: false,
    users: ["#8be9fd", "#50fa7b", "#ffb86c", "#ff79c6", "#bd93f9", "#f1fa8c"],
  },
  {
    name: "gruvbox",
    font: "JetBrains Mono",
    bg: "#282828", text: "#ebdbb2", muted: "#928374",
    accent: "#fabd2f", accent2: "#fe8019",
    success: "#b8bb26", warn: "#fabd2f", error: "#fb4934",
    rainbow: false,
    users: ["#fabd2f", "#b8bb26", "#8ec07c", "#83a598", "#d3869b", "#fe8019"],
  },
  {
    name: "solarized",
    font: "JetBrains Mono",
    bg: "#002b36", text: "#93a1a1", muted: "#586e75",
    accent: "#268bd2", accent2: "#2aa198",
    success: "#859900", warn: "#b58900", error: "#dc322f",
    rainbow: false,
    users: ["#268bd2", "#2aa198", "#859900", "#b58900", "#d33682", "#6c71c4"],
  },
];

export const THEME_NAMES = THEMES.map((t) => t.name);

const byName = new Map(THEMES.map((t) => [t.name, t]));

export function getTheme(name: string): Theme | undefined {
  return byName.get(name);
}

export function defaultTheme(): Theme {
  return THEMES[0];
}
