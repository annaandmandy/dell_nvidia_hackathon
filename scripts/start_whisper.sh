#!/bin/bash
# Serve whisper-large-v3-turbo (copied from SSD to ~/models) with the same vLLM image NemoClaw uses.
# OpenAI-compatible: POST http://localhost:5001/v1/audio/transcriptions  (model=whisper)
set -euo pipefail
IMAGE=nvcr.io/nvidia/vllm@sha256:9204569b17ee4c0eff75194b8e6e458479c8aee18953b5ab9cf359fcdac659e2
MODEL_DIR="${WHISPER_MODEL_DIR:-$HOME/models/whisper-large-v3-turbo}"
[ -f "$MODEL_DIR/model.safetensors" ] || rsync -a --exclude .cache "/media/dell/One Touch/mergeops/hf/whisper-large-v3-turbo/" "$MODEL_DIR/"
docker rm -f mergeops-whisper >/dev/null 2>&1 || true
docker run -d --gpus all --ipc=host --name mergeops-whisper --restart unless-stopped \
  -p 5001:8000 -v "$MODEL_DIR:/model:ro" --entrypoint vllm "$IMAGE" \
  serve /model --served-model-name whisper --gpu-memory-utilization 0.08 --max-model-len 448
echo "Waiting for Whisper on :5001 ..."
until curl -sf http://localhost:5001/v1/models >/dev/null; do
  docker ps -q -f name=mergeops-whisper | grep -q . || { docker logs --tail 40 mergeops-whisper; exit 1; }
  sleep 5
done
echo "Whisper ready."
