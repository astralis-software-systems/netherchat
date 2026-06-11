# Example: a small Netherchat room topology managed as code.
#
# `terraform apply` writes the rooms/routes/trust pins/action policies below into
# netherchat.toml, leaving any hand-written [server]/[limits]/[persistence]
# sections untouched. Point the relay at the same file.

terraform {
  required_providers {
    netherchat = {
      source = "salehkreiner/netherchat"
    }
  }
}

provider "netherchat" {
  config_path = "netherchat.toml"

  # Uncomment to fail `terraform apply` on an invalid topology, checked against a
  # running relay (sends only the rendered config, never message content):
  # validate_url = "https://relay.example.com/api/v1/config/validate"
}

# An invite-only operations room with a webhook and a 24h lifetime.
resource "netherchat_room" "ops" {
  name          = "ops"
  invite_only   = true
  webhook       = true
  webhook_token = var.ops_webhook_token
  ttl           = "24h"
}

# A break-glass route: a high-severity inbound signal spawns an "inc-<8hex>" room
# and invites the on-call responders.
resource "netherchat_route" "incidents" {
  room_prefix = "inc"
  action      = "break-glass"
  match = {
    severity = "high"
  }
  invite = ["@alice", "@bob"]
  ttl    = "12h"
}

# Pin two responders' identities so /whois warns on a fingerprint mismatch.
resource "netherchat_trust" "alice" {
  handle   = "alice"
  fpr      = "SHA256:examplealiceFINGERPRINTexamplealiceFINGER"
  keys_url = "https://github.com/alice.keys"
}

resource "netherchat_trust" "bob" {
  handle   = "bob"
  keys_url = "https://github.com/bob.keys"
}

# Require two distinct co-signers to scuttle a room (the Two-Person Rule).
resource "netherchat_action_policy" "scuttle" {
  action = "scuttle"
  quorum = 2
}

variable "ops_webhook_token" {
  type      = string
  sensitive = true
}
