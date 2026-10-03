#!/bin/bash
# Copy Qwen3.6-35B-A3B-NVFP4 from the SSD into the HF cache layout NemoClaw's managed vLLM expects,
# under the revision NemoClaw pins (LFS weights are identical to the SSD's 1355db6 snapshot).
set -euo pipefail
SRC="${1:-/media/dell/One Touch/mergeops/hf/qwen3-35b-nvfp4}"
R=491c2f1ea524c639598bf8fa787a93fed5a6fbce
M=~/.cache/huggingface/hub/models--nvidia--Qwen3.6-35B-A3B-NVFP4
mkdir -p "$M/snapshots/$R" "$M/refs"
echo -n "$R" > "$M/refs/main"
rsync -a --info=progress2 --exclude .cache "$SRC/" "$M/snapshots/$R/"
