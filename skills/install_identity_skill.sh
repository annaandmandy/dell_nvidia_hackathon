#!/bin/bash
# Sync data/roles.json into the identity skill and (re)install it into the sandbox.
# Re-run after editing data/roles.json.
set -euo pipefail
cd "$(dirname "$0")/.."
SANDBOX="${1:-my-assistant}"
cp data/roles.json skills/mergeops-identity/roles.json
nemoclaw "$SANDBOX" skill install skills/mergeops-identity
