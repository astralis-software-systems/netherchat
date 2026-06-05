# Commands & keys

## Slash commands (TUI)

Type these in the message box. Tab completes command names and arguments.

| Command | Description |
|---|---|
| `/help` | List all commands. |
| `/theme <name>` | Switch theme instantly. Names: `nether`, `abyss`, `ember`, `ghost`, `sprinkles`, `dracula`, `gruvbox`, `solarized`. |
| `/font` | Show the recommended terminal font for the current theme (advisory — a TUI cannot change the terminal font; the web client honors fonts directly). |
| `/whoami` | Show your identity fingerprint, the room, encryption status, and room policy. |
| `/invite` | Mint a one-time invite token for the current room and display it as a QR code. |
| `/vanish` | Rotate the room key forward (HKDF ratchet) and clear history for everyone — messages from before are no longer decryptable. |
| `/ttl <dur\|off>` | Set a client-side message display TTL (e.g. `/ttl 1h`, `/ttl off`). |
| `/exec <command>` | Run an allow-listed command on the server (must be enabled in `netherchat.toml`). |
| `/join <room>` | Join another room (opens a new tab in the sidebar). |
| `/leave` | Leave the current room. |
| `/clear` | Clear the current room view locally. |
| `/quit` | Quit. |

## Keys

| Key | Action |
|---|---|
| `Enter` | Send the message / run the command |
| `Tab` | Accept the highlighted autocomplete suggestion |
| `↑` / `↓` | Move the suggestion selection, or scroll history when there are none |
| `PgUp` / `PgDn`, mouse wheel | Scroll history |
| `Ctrl+N` / `Ctrl+P` | Next / previous room |
| click a room | Focus it |
| `Esc` / `Ctrl+C` | Quit |

## Non-interactive CLI

For scripts and pipelines (plain text, no styling):

```bash
# Send one message (or pipe it via stdin)
echo "build failed on main" | netherchat send ops --server ws://chat.example.com
netherchat send ops "deploy complete" --server ws://chat.example.com

# Stream a room's decrypted messages to stdout
netherchat tail alerts --server ws://chat.example.com | grep CRITICAL | tee crit.log
```

Common flags: `--server <url>`, `--name <you>`, `--identity <path>`, `--invite <token>`.

> `send` and `tail` join the room as ordinary E2E members, so they can only
> exchange messages while at least one other member is present to share the room
> key. For unattended, no-key injection from external systems, use an inbound
> [webhook](self-hosting.md) instead (server-origin plaintext).
