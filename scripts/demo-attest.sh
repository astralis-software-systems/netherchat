#!/usr/bin/env bash
# NC-W3 demo: Agent-Decision Attestation — the full propose -> approve -> seal ->
# verify loop, offline, using only netherchat binaries + curl (and a standard
# sha256 tool to hash the sample artifact). It shows:
#   - an agent signalling "artifact_produced" auto-spawns a war room (detection)
#   - an agent PROPOSING an artifact (by hash, never content)
#   - a named human APPROVING it under the Two-Person Rule (the agent can never
#     self-approve)
#   - the signed "artifact" record entry sealing into an offline-verifiable record
#   - tamper detection
#   - a leadership report rendering "AI drafted, a human approved"
#
# Usage:  scripts/demo-attest.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ADDR="127.0.0.1:3000"
HTTP="http://${ADDR}"
WS="ws://${ADDR}"
WORK="$(mktemp -d)"
TOKEN="demo-token-please-rotate"
ROOM="attest-ops"
SERVER_PID=""
APPROVE_PID=""

cleanup() {
  [ -n "$APPROVE_PID" ] && kill "$APPROVE_PID" 2>/dev/null || true
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[1;35m== %s\033[0m\n' "$1"; }

hash_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}';
  else echo "need sha256sum or shasum to hash the artifact" >&2; exit 1; fi
}

say "1. Build the relay, client, and adapters"
go build -o "$WORK/bin/" ./cmd/...
PATH="$WORK/bin:$PATH"

say "2. Relay config: a source + an artifact route + the artifact quorum"
cat > "$WORK/netherchat.toml" <<EOF
[server]
addr = "${ADDR}"

[[source]]
name = "requirements-agent"
token = "${TOKEN}"

# A produced-artifact signal opens a war room for human review.
[[route]]
match = { source = "requirements-agent", kind = "artifact_produced" }
action = "break-glass"
invite = ["alice", "bob"]
room_prefix = "review"
ttl = "1h"

# One human approver is required to seal an agent-produced artifact.
[action.artifact]
quorum = 1
EOF

say "3. Start the blind relay"
netherchat-server -config "$WORK/netherchat.toml" >/dev/null 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  if curl -fsS "${HTTP}/health" >/dev/null 2>&1; then break; fi
  sleep 0.1
done
curl -fsS "${HTTP}/health" >/dev/null || { echo "relay did not become healthy"; exit 1; }
echo "relay healthy on ${ADDR}"

say "4. The agent produces an artifact — its CONTENT never crosses, only its hash"
cp "$ROOT/scripts/sample-artifact.txt" "$WORK/artifact.txt"
HASH="$(hash_of "$WORK/artifact.txt")"
echo "artifact: $WORK/artifact.txt"
echo "sha256:  $HASH   (the ONLY representation of the content that ever crosses)"

say "5. The agent signals 'artifact_produced' → the relay auto-spawns a war room"
cat > "$WORK/event.json" <<EOF
{
  "event_id":     "evt-q3-001",
  "severity":     "high",
  "kind":         "artifact_produced",
  "source":       "requirements-agent",
  "artifact_ref": "Q3-requirements",
  "artifact_hash":"${HASH}",
  "summary":      "Q3 requirements draft ready for human review",
  "ts":           "2026-06-12T10:00:00Z"
}
EOF
netherchat-agent-adapter --event "$WORK/event.json" \
  --server "$HTTP" --source requirements-agent --token "$TOKEN" || true

say "6. The attest loop: the agent proposes, a human approves, the record seals"
echo "alice (a human) joins room #${ROOM} and waits for the proposal …"
# Two DISTINCT identities: the agent can never approve its own proposal (the second law).
netherchat approve-artifact --server "$WS" --room "$ROOM" \
  --identity "$WORK/alice.json" --name alice --wait 300s \
  --seal --out "$WORK/record.json" >"$WORK/approve.log" 2>&1 &
APPROVE_PID=$!
# Wait until alice is connected and watching, so the proposal is never sent into an
# empty room (a proposal has no replay). This is robust to slow process startup.
for _ in $(seq 1 150); do
  grep -q "approve-artifact ready" "$WORK/approve.log" 2>/dev/null && break
  sleep 0.2
done
grep -q "approve-artifact ready" "$WORK/approve.log" || { echo "alice did not become ready"; cat "$WORK/approve.log"; exit 1; }

echo "requirements-agent proposes the artifact (by hash) …"
netherchat propose --server "$WS" --room "$ROOM" \
  --identity "$WORK/agent.json" --source requirements-agent \
  --ref "Q3-requirements" --hash "$HASH" --summary "Q3 requirements draft for review"

wait "$APPROVE_PID"; APPROVE_PID=""
cat "$WORK/approve.log"

[ -f "$WORK/record.json" ] || { echo "no record.json was produced"; exit 1; }

say "7. Verify the sealed record offline"
netherchat verify "$WORK/record.json"

say "8. Tamper one field → verification detects it"
sed 's/Q3-requirements/Q4-requirements/g' "$WORK/record.json" > "$WORK/tampered.json"
echo "(changed the signed artifact reference in one entry)"
if netherchat verify "$WORK/tampered.json"; then
  echo "ERROR: a tampered record verified — this must never happen"; exit 1
else
  echo "tamper correctly detected (verify exited non-zero)"
fi

say "9. Leadership report — 'AI drafted, alice approved', human-readable"
netherchat report "$WORK/record.json" --executive --out "$WORK/report.html"
netherchat report "$WORK/record.json" --format md --out "$WORK/report.md"
echo "--- executive report (markdown) ---"
sed -n '1,40p' "$WORK/report.md"
echo
echo "HTML report: $WORK/report.html  (open in a browser)"

say "done — propose → approve → seal → verify, fully offline"
