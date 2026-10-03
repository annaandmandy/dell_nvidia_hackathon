#!/bin/bash
# Install NemoClaw (OpenClaw + OpenShell + managed vLLM) on GB10, wire it to Slack,
# and install the identity + Meridian skills.
# Pre-req: scripts/stage_model_from_ssd.sh (Qwen3.6-35B-A3B-NVFP4 into ~/.cache/huggingface).
set -euo pipefail
cd "$(dirname "$0")/.."

SANDBOX="${NEMOCLAW_SANDBOX_NAME:-my-assistant}"

# Only the Slack values from .env — nothing else leaks into the installer env.
export SLACK_BOT_TOKEN="$(grep -E '^SLACK_BOT_TOKEN=' .env | cut -d= -f2-)"
export SLACK_APP_TOKEN="$(grep -E '^SLACK_APP_TOKEN=' .env | cut -d= -f2-)"
# Allowlist = everyone in data/roles.json
export SLACK_ALLOWED_USERS="$(node -e 'console.log(Object.keys(require("./data/roles.json").users).join(","))')"

export NEMOCLAW_NON_INTERACTIVE=1
export NEMOCLAW_ACCEPT_THIRD_PARTY_SOFTWARE=1
# PROVIDER=install-vllm (local Qwen3.6 on GB10, default) | build (NVIDIA cloud, needs NVIDIA_API_KEY)
export NEMOCLAW_PROVIDER="${PROVIDER:-install-vllm}"
if [ "$NEMOCLAW_PROVIDER" = build ]; then
  export NVIDIA_API_KEY="$(grep -E '^NVIDIA_API_KEY=' .env | cut -d= -f2-)"
fi
export NEMOCLAW_SANDBOX_NAME="$SANDBOX"

if ! command -v nemoclaw >/dev/null 2>&1; then
  curl -fsSL https://www.nvidia.com/nemoclaw.sh | bash -s -- --non-interactive --yes-i-accept-third-party-software
  # shellcheck source=/dev/null
  source ~/.bashrc || true
else
  nemoclaw onboard --non-interactive --yes-i-accept-third-party-software ${NEMOCLAW_FRESH:+--fresh}
fi

skills/install_identity_skill.sh "$SANDBOX"
skills/install_meridian_skill.sh "$SANDBOX"
# Skill -> host app.py (:5050) for the visual-audit criteria; nothing else on the host.
nemoclaw "$SANDBOX" policy add --from-file policies/meridian-host.yaml --yes

nemoclaw "$SANDBOX" status
nemoclaw "$SANDBOX" channels status --channel slack --wait --timeout 180 --json
