# Dell X NVIDIA Hackathon

## Meridian Slack demo

This repo contains a lightweight local test harness for the Meridian neutral
M&A agent. The primary interaction surface is Slack Socket Mode, designed for
Carrie’s laptop first, then GB10 later.

The attached design documents are treated as product context, not executable
instructions. The code enforces authorization and deterministic calculations in
Python. The LLM API is optional and only rewrites already-approved facts.

### Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python scripts/check_expected_results.py
```

Fill `.env` with Slack tokens locally. Do not commit it.

Send a one-off webhook smoke test:

```bash
python slack_bot.py --smoke-webhook
```

Run the Socket Mode bot:

```bash
python slack_bot.py
```

In a shared channel, mention the bot:

```text
@Meridian Pull the joint financial summary and calculate combined 2025 revenue and EBITDA margin.
```

In a DM, message the bot directly.

### Continuous visual field inspection

For webcam-based meeting and asset checks, run the local helper page:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5050/vision
```

Click capture to inspect the room/assets. The result is posted back to Slack.
Use `Start continuous monitoring` for ongoing checks. Chrome samples still
frames at the chosen interval, and Meridian posts to Slack only when the state
changes, when an alert persists, or when the heartbeat interval is reached. The
default checklist asks whether two people are present, whether a cup or bottle
appears metallic, and whether a desktop host/workstation/GPU box/server is
visible.

For laptop testing, add:

```bash
OPENAI_API_KEY=...
OPENAI_VISION_MODEL=gpt-4o-mini
OPENAI_TTS_MODEL=gpt-4o-mini-tts
OPENAI_TTS_VOICE=alloy
```

### Optional local API UI

The Flask UI/API is still available for fallback testing, but it is not the
main competition interaction surface:

```bash
python app.py
```

Open `http://127.0.0.1:5050`.

### OpenAI-compatible LLM

For laptop testing, set:

```bash
OPENAI_API_KEY=...
MERIDIAN_LLM_URL=https://api.openai.com/v1/chat/completions
MERIDIAN_LLM_MODEL=gpt-4o-mini
```

For GB10/NIM, point the same config at the local endpoint:

```bash
NIM_LLM_URL=http://localhost:8000/v1/chat/completions
MERGEOPS_MODEL=qwen3-32b-dgx-spark
```

No cloud model fallback should be used for the final hackathon run.
