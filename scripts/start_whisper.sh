#!/bin/bash
# Serve whisper-large-v3-turbo (copied from SSD to ~/models) with the same vLLM image NemoClaw uses.
# OpenAI-compatible: POST http://localhost:5001/v1/audio/transcriptions  (model=whisper)
set -euo pipefail
BASE_IMAGE=nvcr.io/nvidia/vllm@sha256:9204569b17ee4c0eff75194b8e6e458479c8aee18953b5ab9cf359fcdac659e2
# vLLM decodes uploaded audio with PyAV, which the NGC image lacks. The first run installs it and
# saves the result as a local image, so later runs (and reboots) need no network.
LOCAL_IMAGE=mergeops/whisper-vllm:local
MODEL_DIR="${WHISPER_MODEL_DIR:-$HOME/models/whisper-large-v3-turbo}"
[ -f "$MODEL_DIR/model.safetensors" ] || rsync -a --exclude .cache "/media/dell/One Touch/mergeops/hf/whisper-large-v3-turbo/" "$MODEL_DIR/"
docker rm -f mergeops-whisper >/dev/null 2>&1 || true
if docker image inspect "$LOCAL_IMAGE" >/dev/null 2>&1; then
  IMAGE="$LOCAL_IMAGE"; CMD='vllm serve /model --served-model-name whisper --gpu-memory-utilization 0.08 --max-model-len 448'
else
  IMAGE="$BASE_IMAGE"; CMD='pip install -q av && vllm serve /model --served-model-name whisper --gpu-memory-utilization 0.08 --max-model-len 448'
fi
docker run -d --gpus all --ipc=host --name mergeops-whisper --restart unless-stopped \
  -p 5001:8000 -v "$MODEL_DIR:/model:ro" --entrypoint sh "$IMAGE" -c "$CMD"
echo "Waiting for Whisper on :5001 ..."
until curl -sf http://localhost:5001/v1/models >/dev/null; do
  docker ps -q -f name=mergeops-whisper | grep -q . || { docker logs --tail 40 mergeops-whisper; exit 1; }
  sleep 5
done
[ "$IMAGE" = "$LOCAL_IMAGE" ] || docker commit mergeops-whisper "$LOCAL_IMAGE" >/dev/null
echo "Whisper ready."
