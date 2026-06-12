#!/usr/bin/env bash
# NC-2 demo: the detect -> respond -> attest loop, using only netherchat binaries
# and curl. Steps 1-2 (detection -> auto-spawned war room) are fully automated;
# steps 4-6 (the in-room, two-person attest) are deliberately human (the second
# law: only people authorize actions), so the script prints the exact commands and
# then verifies a sealed record if one is present.
#
# Usage:  scripts/demo-nc2.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ADDR="127.0.0.1:3000"
HTTP="http://${ADDR}"
WS="ws://${ADDR}"
WORK="$(mktemp -d)"
TOKEN="demo-token-please-rotate"
SERVER_PID=""

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[1;35m== %s\033[0m\n' "$1"; }

say "1. Build the relay and adapters"
go build -o "$WORK/bin/" ./cmd/...
PATH="$WORK/bin:$PATH"

say "2. Write a relay config: one source + a catch-all route"
cat > "$WORK/netherchat.toml" <<EOF
[server]
addr = "${ADDR}"

[[source]]
name = "demo-scanner"
token = "${TOKEN}"

[[route]]
match = { source = "demo-scanner", severity = "high|critical" }
action = "break-glass"
invite = ["alice", "bob"]
room_prefix = "inc"
ttl = "1h"
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

say "4. A security finding arrives (note: description/remediation are NOT forwarded)"
cat > "$WORK/finding.json" <<'EOF'
{
  "finding_id":  "f-001",
  "severity":    "high",
  "check_id":    "CIS-1.20",
  "resource":    "arn:aws:s3:::public-bucket",
  "region":      "us-east-1",
  "title":       "S3 bucket allows public read",
  "description": "SENSITIVE DETAIL — stays at the source, never forwarded",
  "remediation": "SENSITIVE STEPS — stays at the source, never forwarded",
  "ts":          "2026-06-12T10:00:00Z"
}
EOF
cat "$WORK/finding.json"

say "5. Forward it through the findings adapter -> the relay auto-spawns a war room"
OUT="$(netherchat-findings-adapter --finding "$WORK/finding.json" \
  --server "$HTTP" --source demo-scanner --token "$TOKEN")"
echo "$OUT"

ROOM="$(printf '%s\n' "$OUT" | sed -n 's/.*war room \([^ ]*\) spawned.*/\1/p' | head -n1)"
echo
echo "Active rooms on the relay:"
netherchat rooms --server "$WS" || true

say "6. Respond + attest (HUMAN — two operators, two terminals)"
cat <<EOF
The relay opened war room: ${ROOM:-<see links above>}
Each responder joins with their one-time link printed above, e.g.:

  netherchat connect ${WS} --room ${ROOM:-<room>} --name alice --invite <ALICE_TOKEN>
  netherchat connect ${WS} --room ${ROOM:-<room>} --name bob   --invite <BOB_TOKEN>

Then, in the room:

  /decide contained: bucket set private, keys rotated
  /action @bob file the incident report
  /seal        # alice proposes
  /seal        # bob co-signs -> writes record.json

This step is intentionally not automated: sealing is a human, cryptographic
two-person action inside the E2E room. Detection rang the bell; people decide.
EOF

say "7. Verify the sealed record offline"
if [ -f "record.json" ]; then
  netherchat verify record.json
else
  cat <<EOF
No record.json yet — run the attest step above, then:

  netherchat verify record.json

For a fully-automated proof of the entire loop (alert -> spawn -> join -> decide ->
action -> two-party seal -> verify), run:

  go test ./tui/e2e/ -run TestNC2DetectRespondAttest -v
EOF
fi

say "done"
