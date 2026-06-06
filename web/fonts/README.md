# Brand fonts (self-hosted)

Netherchat self-hosts its fonts — it makes **no outbound requests** at runtime
(no Google Fonts), in keeping with the project's zero-telemetry stance. The
`.woff2` binaries are intentionally **not committed**; fetch them once into
`web/public/fonts/` and Vite will ship them with the build.

Until you run the fetch, the UI still renders correctly: `styles/fonts.css`
declares each face with a `local()` source first (used if you already have the
font installed) and falls back through the system stacks in `--font-ui` /
`--font-mono` if neither the local nor the self-hosted file is present.

## Fetch

```bash
# macOS / Linux
./fonts/fetch-fonts.sh
```

```powershell
# Windows
./fonts/fetch-fonts.ps1
```

Both download the regular/medium/semibold weights of the four brand fonts from
their official, OFL-licensed releases and write them to `web/public/fonts/`:

| Font           | Used by themes              | License |
|----------------|-----------------------------|---------|
| Space Grotesk  | UI (all)                    | OFL 1.1 |
| JetBrains Mono | nether, abyss, ember, …     | OFL 1.1 |
| IBM Plex Mono  | ghost                       | OFL 1.1 |
| Fira Code      | sprinkles                   | OFL 1.1 |

The exact filenames `styles/fonts.css` expects are listed in the scripts.
