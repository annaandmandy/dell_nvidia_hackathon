#!/bin/bash
# Sync data/roles.json into the identity skill, (re)install it into the sandbox, and
# inject the generated team directory into the agent's AGENTS.md (loaded every session).
# Re-run after editing data/roles.json.
set -euo pipefail
cd "$(dirname "$0")/.."
SANDBOX="${1:-my-assistant}"
WS=/sandbox/.openclaw/workspace
cp data/roles.json skills/mergeops-identity/roles.json
nemoclaw "$SANDBOX" skill install skills/mergeops-identity

# Replace the marked block in AGENTS.md (or append it the first time).
nemoclaw "$SANDBOX" exec -- sh -c "
  set -e
  cd $WS
  sed -i '/<!-- mergeops-directory:start/,/<!-- mergeops-directory:end -->/d' AGENTS.md
  printf '\n' >> AGENTS.md
  node skills/mergeops-identity/identify.mjs directory 2>/dev/null >> AGENTS.md
  grep -c 'mergeops-directory' AGENTS.md
"
