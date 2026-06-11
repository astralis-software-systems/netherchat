# terraform-provider-netherchat

Manage a Netherchat **room topology as code** — rooms, signal routes, trust pins,
and Two-Person-Rule action policies — by declaring them in Terraform and letting
the provider maintain the corresponding sections of `netherchat.toml`.

This is the same config-as-code ethos the relay already follows (`netherchat.toml`
is the operator's source of truth); the provider just lets you express and version
that file from Terraform alongside the rest of your infrastructure.

> **Separate module on purpose.** This provider lives outside the main Netherchat
> `go.mod`. The heavyweight Terraform plugin SDK never touches the core, so the
> `netherchat` / `netherchat-server` binaries stay pure-Go, `CGO_ENABLED=0`,
> minimal-dependency static binaries. The provider depends only on the SDK and
> `go-toml/v2` — it does **not** import the Netherchat core.

## What it manages (and what it leaves alone)

The provider edits **only** the sections backing its resources. Every other
section of `netherchat.toml` — `[server]`, `[limits]`, `[persistence]`, and
anything else you hand-write — survives a round-trip **untouched**. You can mix
Terraform-managed and hand-written config in the same file.

| Resource | TOML section | Keyed by |
|---|---|---|
| `netherchat_room` | `[rooms.<name>]` | `name` |
| `netherchat_route` | `[[route]]` | `room_prefix` |
| `netherchat_trust` | `[[trust]]` | `handle` |
| `netherchat_action_policy` | `[action.<name>]` | `action` |

## Provider configuration

```hcl
provider "netherchat" {
  # Path to the netherchat.toml to manage.
  # Default: ./netherchat.toml  (or $NETHERCHAT_CONFIG)
  config_path = "netherchat.toml"

  # OPTIONAL. URL of a running relay's read-only validation endpoint. When set,
  # each change is checked against the relay BEFORE it is written, so an invalid
  # topology fails `terraform apply` instead of a later server restart. It sends
  # only the rendered netherchat.toml — never message content. Leave empty (the
  # default) to edit the file purely offline.
  # Also settable via $NETHERCHAT_VALIDATE_URL.
  validate_url = "https://relay.example.com/api/v1/config/validate"
}
```

## Resources

### `netherchat_room`

| Attribute | Type | Notes |
|---|---|---|
| `name` | string, required, ForceNew | table key under `[rooms]` |
| `invite_only` | bool | only invited members may join |
| `webhook` | bool | expose an inbound webhook for this room |
| `webhook_token` | string, sensitive | bearer token for the room's webhook |
| `exec_enabled` | bool | advisory flag for `/exec`; enforcement is agent-side |
| `beacon_token` | string, sensitive | token for the room's read-only status beacon |
| `beacon_ttl` | string | lifetime of a published beacon snapshot, e.g. `"15m"` |
| `ttl` | string | hard lifetime of the room, e.g. `"24h"` |

### `netherchat_route`

A signal route: an inbound metadata alert that matches `match` spawns a room.

| Attribute | Type | Notes |
|---|---|---|
| `room_prefix` | string, required, ForceNew | spawned room is `<prefix>-<8hex>`; the route's identity |
| `action` | string | currently only `"break-glass"` (default) |
| `match` | map(string) | field=value conditions an inbound signal must satisfy |
| `invite` | list(string) | display names / `@handles` to invite into the spawned room |
| `ttl` | string | hard lifetime of the spawned room |
| `reply_url` | string | optional URL to POST the generated room links back to |

### `netherchat_trust`

A trust pin binding a handle to a fingerprint and/or a published key source.
Evaluated **client-side only** (`/whois`) — the relay never reads it.

| Attribute | Type | Notes |
|---|---|---|
| `handle` | string, required, ForceNew | the handle being pinned |
| `fpr` | string | pinned fingerprint, e.g. `"SHA256:…"` |
| `keys_url` | string | e.g. `https://github.com/<handle>.keys` |

### `netherchat_action_policy`

A Two-Person-Rule quorum gate for a dangerous action. Enforcement is client-side
and cryptographic (N-of-M Ed25519 co-signatures); the relay only ever sees
ciphertext.

| Attribute | Type | Notes |
|---|---|---|
| `action` | string, required, ForceNew | the action being gated, e.g. `"scuttle"` |
| `quorum` | int, required | distinct signers required (`1` = single-actor; `0` disables) |

## Import

Every resource imports by its identity key:

```sh
terraform import netherchat_room.ops               ops
terraform import netherchat_route.incidents        inc
terraform import netherchat_trust.alice            alice
terraform import netherchat_action_policy.scuttle  scuttle
```

## Build & local install

```sh
cd terraform-provider-netherchat
go build -o terraform-provider-netherchat

# Install into the Terraform CLI plugin dirs, or use a dev_overrides block in
# ~/.terraformrc pointing at this directory for local development.
```

A worked configuration lives in [`examples/main.tf`](examples/main.tf).

## Tests

The TOML round-trip and unmanaged-section-preservation logic — the crux of the
provider — is unit-tested without compiling the SDK:

```sh
go test ./internal/tfconfig/
```
