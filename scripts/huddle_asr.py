#!/usr/bin/env python3
"""
Huddle ASR — capture a Slack huddle from a Chrome tab, transcribe with local Whisper.

Chrome (Slack huddle tab audio + local mic) → POST /api/audio (16 kHz mono WAV, ~5 s)
  → vLLM Whisper (WHISPER_URL, OpenAI /v1/audio/transcriptions)
  → data/meeting/huddle_transcript.jsonl
  → War Room POST /api/meeting/chunk (WARROOM_CHUNK_URL), if it is running

Open http://localhost:3002 in Chrome on the machine that is in the huddle.
"""
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

sys.stdout = open(sys.stdout.fileno(), mode="w", buffering=1, closefd=False)

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

WHISPER_URL = os.environ.get("WHISPER_URL", "http://localhost:5001/v1/audio/transcriptions")
WHISPER_MODEL = os.environ.get("WHISPER_MODEL", "whisper")
WHISPER_LANGUAGE = os.environ.get("WHISPER_LANGUAGE", "en")  # "" = auto-detect
WARROOM_CHUNK_URL = os.environ.get("WARROOM_CHUNK_URL", "http://localhost:3001/api/meeting/chunk")
PORT = int(os.environ.get("HUDDLE_ASR_PORT", "3002"))

TRANSCRIPT = ROOT / "data" / "meeting" / "huddle_transcript.jsonl"
TRANSCRIPT.parent.mkdir(parents=True, exist_ok=True)

# Whisper's well-known hallucinations on near-silent audio.
HALLUCINATIONS = {
    "", "you", "thank you", "thank you.", "thanks for watching!", "thanks for watching.",
    "bye.", "bye", ".", "...", "so", "okay.", "[blank_audio]", "(silence)",
}

app = Flask(__name__, static_folder=str(ROOT / "scripts" / "static"))


def transcribe(wav: bytes) -> str:
    data = {"model": WHISPER_MODEL, "response_format": "json", "temperature": "0"}
    if WHISPER_LANGUAGE:
        data["language"] = WHISPER_LANGUAGE
    resp = requests.post(
        WHISPER_URL, files={"file": ("chunk.wav", wav, "audio/wav")}, data=data, timeout=30
    )
    resp.raise_for_status()
    return resp.json().get("text", "").strip()


def forward_to_warroom(text: str, stamp: str) -> bool:
    try:
        r = requests.post(WARROOM_CHUNK_URL, json={"text": text, "timestamp": stamp}, timeout=5)
        return r.ok
    except requests.RequestException:
        return False


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "huddle_capture.html")


@app.route("/api/audio", methods=["POST"])
def audio():
    wav = request.get_data()
    if not wav:
        return jsonify({"error": "empty body"}), 400
    t0 = time.time()
    try:
        text = transcribe(wav)
    except requests.RequestException as e:
        print(f"[asr] whisper error: {e}")
        return jsonify({"error": f"whisper unavailable: {e}"}), 502
    if text.lower() in HALLUCINATIONS:
        return jsonify({"text": "", "skipped": True})
    stamp = datetime.now().strftime("%H:%M:%S")
    forwarded = forward_to_warroom(text, stamp[:5])
    with TRANSCRIPT.open("a") as f:
        f.write(json.dumps({"t": stamp, "text": text, "forwarded": forwarded}) + "\n")
    print(f"[asr] {stamp} ({time.time() - t0:.1f}s) {'→WR ' if forwarded else ''}{text}")
    return jsonify({"t": stamp, "text": text, "forwarded": forwarded})


@app.route("/api/transcript")
def transcript():
    if not TRANSCRIPT.exists():
        return jsonify([])
    lines = TRANSCRIPT.read_text().splitlines()[-200:]
    return jsonify([json.loads(l) for l in lines if l.strip()])


@app.route("/health")
def health():
    try:
        whisper_ok = requests.get(WHISPER_URL.split("/v1/")[0] + "/v1/models", timeout=3).ok
    except requests.RequestException:
        whisper_ok = False
    return jsonify({"status": "ok", "whisper": whisper_ok, "language": WHISPER_LANGUAGE or "auto"})


if __name__ == "__main__":
    print(f"Huddle ASR on http://localhost:{PORT}  (whisper: {WHISPER_URL})")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
