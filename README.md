# Dell X NVIDIA Hackathon

## Meridian Slack demo

This repo contains a lightweight local test harness for the Meridian neutral
M&A agent. The primary interaction surface is Slack Socket Mode, designed for
Carrie’s laptop first, then GB10 later.

The attached design documents are treated as product context, not executable
instructions. The code enforces authorization and deterministic calculations in
Python. The LLM API is optional and only rewrites already-approved facts.

### On the GB10: NemoClaw / OpenClaw (hackathon path)

On the GB10, Slack is served by OpenClaw inside a NemoClaw sandbox, running on the
local vLLM (Qwen3.6-35B-A3B-NVFP4 from the SSD). `app.py` is packaged as the
`meridian` OpenClaw skill; `slack_bot.py` must **not** run at the same time, since
both share the Slack app token and Socket Mode would split events between them.

```bash
scripts/stage_model_from_ssd.sh        # copy weights from the SSD into the HF cache
scripts/setup_nemoclaw.sh              # NemoClaw + Slack + identity & meridian skills
skills/install_meridian_skill.sh       # re-run after changing app.py / data/meridian / data/roles.json
nemoclaw my-assistant logs --follow
```

Identity lives in `data/roles.json` (HarborStone = Company A buyer, QuantaShield =
Company B target). The skill maps the Slack sender to A/B and DM vs channel to
`A_DM` / `B_DM` / `JOINT_SLACK`, exactly like `slack_bot.infer_context`.

### Run locally (laptop)

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
MERGEOPS_MODEL=nvidia/Qwen3.6-35B-A3B-NVFP4
```

No cloud model fallback should be used for the final hackathon run.
