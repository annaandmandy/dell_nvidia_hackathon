# Meridian — Developer Notes

> Judge-facing overview: see the top-level [README](../README.md). This file keeps the detailed run notes.

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

Meridian reads everything from `meridian_finance_ai_demo_bundle/` (registry, signed
disclosures, joint-approved summaries, clean-room recompute). Signatures are checked with
`ed25519_verify.py` (pure Python, so it also runs inside the sandbox). Acceptance checks
(meeting script, the ten attack tests, figures): `python scripts/check_expected_results.py`.

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

Run the unified meeting console:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5050/meeting
```

Use `Start Meeting` and `End Meeting`. Start Meeting runs continuous voice
listening and continuous visual monitoring together; results go to Slack. End
Meeting generates downloadable meeting summary and transcription files.

On the GB10 the meeting console is the default page (`/`); the ask console moved to
`/console`. Voice and vision run on the local Whisper and Qwen3.6 VLM. Spoken requests and
owner-authorized disclosures (`you can share our top customers with HarborStone`, said by
the owner) go through the same Meridian policy as Slack. Uploading the summary/transcript
files to Slack needs the `files:write` bot scope; without it they stay downloadable here.

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
@Meridian Pull QuantaShield's commercial summary. Is the 115 million valuation supported?
```

In a DM, message the bot directly.

### Deal room (demo opening)

```bash
python app.py        # then open http://127.0.0.1:5050/deal-room
```

`New deal room` (or `@Meridian start a new deal room` in Slack) clears uploads, archives the
audit trail and resets the meeting monitors. Each party then uploads one signed disclosure:

- HarborStone: `meridian_finance_ai_demo_bundle/signed_inputs/buyer_reliability_authorized.json`
- QuantaShield: `meridian_finance_ai_demo_bundle/signed_inputs/startup_commercial_authorized.json`
- Tamper demo: `ATTACK_tampered_startup_metrics.json` (ARR 11.8 → 15.8) is rejected as INVALID

`@Meridian new deal` opens the room and the bot DMs every person in `data/roles.json` a
personal link (`http://<gb10-ip>:5050/deal-room?t=<token>`). Only that person can read their DM,
so the token stands for their Slack identity: the page shows who is signed in, only their own
party's card accepts uploads, the party is taken from the token (not the form), and the audit
records their Slack ID. From the LAN only the deal-room page/state/upload answer, and only with a
current token; a new room revokes all links. Opening the page on the GB10 itself (no token) is the
host view with both cards. Venue Wi-Fi with client isolation blocks laptop→GB10 traffic; then
open the link on the GB10.

Uploads are Ed25519-verified against the registered issuer key, and a party can only submit
disclosures it issued. The rest of each package is registered from local disk. When both sides
are verified the clean room runs automatically; every step is posted to Slack and audited.

### Continuous voice meeting monitor

The standalone voice page is still available for debugging:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5050/voice
```

Click `Start listening`. Chrome records short audio chunks continuously and
sends them to ASR. Meridian keeps meeting state. For example:

```text
Person A: Can I have your financial statement?
Person B: Yes, go ahead.
```

Meridian detects the request, waits for explicit approval, then posts the
approved financial summary into Slack.

### Continuous visual field inspection

The standalone visual page is still available for debugging:

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5050/vision
```

Click capture to inspect the room/assets. The result is posted back to Slack.
Use `Start continuous monitoring` for ongoing checks. Chrome samples still
frames at the chosen interval and updates the checklist table. Meridian posts
to Slack only at the end:

- `ALLOW` when every configured checkbox is satisfied.
- `DENY` when the monitor is manually stopped before all boxes are checked.

The default checklist asks whether two people are present, whether a cup or
bottle appears metallic, and whether a desktop host/workstation/GPU box/server
is visible.

Change visual audit conditions from Slack:

```text
@Meridian set visual criteria: people=2; metal cup=1; AI host=1
```

Chinese works too:

```text
@Meridian 修改审查条件：两个人；铁水杯；一台主机
```

Show current criteria:

```text
@Meridian show visual criteria
```

On the GB10 everything is local: vision uses the Qwen3.6 VLM on vLLM (:8000), ASR uses
Whisper on vLLM (:5001, start it with `scripts/start_whisper.sh`), and spoken replies use
Chrome's built-in speechSynthesis. The voice page converts each chunk to 16 kHz WAV in the
browser before upload. Results are posted outbound only (chat.postMessage / incoming
webhook), so the meeting monitor never competes with OpenClaw for Slack events.

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
