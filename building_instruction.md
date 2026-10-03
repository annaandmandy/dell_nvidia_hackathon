# MergeOps — Rebuild Reference
# For coding agent / Claude on hackathon day

---

## GB10 Setup — Do This First (30–45 min)

### Step 1: Verify Required Stack

```bash
# All three must be present on GB10
nemoclaw --version
openClaw --version
nemoclaw shell status     # OpenShell
```

If any command fails, ask event staff — GB10 should have these pre-installed.

### Step 2: Load NIM Containers from SSD

```bash
# Find SSD mount point — ask staff or check
lsblk
ls /mnt/ssd 2>/dev/null || ls /media/ 2>/dev/null

SSD="/mnt/ssd"   # adjust to actual path

for f in $SSD/mergeops/nim/*.tar.gz; do
    echo "Loading $f..."
    docker load < $f
done

docker images | grep nim   # verify
```

### Step 3: Start NIM Containers

```bash
# Primary LLM
docker run --gpus all -d -p 8000:8000 \
  nvcr.io/nim/qwen/qwen3-32b-dgx-spark:latest

# ASR (for War Room mic input)
docker run --gpus all -d -p 5001:8000 \
  nvcr.io/nim/nvidia/nemotron-asr-streaming:1.3.1

# Embeddings (for ChromaDB search)
docker run --gpus all -d -p 5002:8000 \
  nvcr.io/nim/nvidia/nemotron-3-embed-1b:latest

# Wait for models to load (~60 seconds)
sleep 60
curl http://localhost:8000/v1/models   # should return model list
```

If NIM fails to start after 15 min → fall back to Ollama (see .env comments).

### Step 4: Start NemoClaw + OpenShell

```bash
# Start NemoClaw assistant (required by hackathon)
nemoclaw my-assistant start

# Verify OpenShell is active
nemoclaw shell status

# Test block/unblock cycle
nemoclaw shell block --id TEST-001 --reason "smoke test"
nemoclaw shell status --id TEST-001
nemoclaw shell execute --id TEST-001 --approved-option "proceed"
echo "OpenShell working ✓"
```

### Step 5: Extract Codebase + Install Dependencies

```bash
# Extract scaffold
cd ~
tar -xzf $SSD/mergeops/mergeops_scaffold.tar.gz
cd dell_nvda_01

# Install Python dependencies
pip install -r requirements.txt
# If pip blocked: pip install --break-system-packages -r requirements.txt

# Verify key imports
python3 -c "import chromadb, flask, slack_bolt, requests; print('deps OK')"
```

### Step 6: Verify Scaffold Data

```bash
# ChromaDB must already be ingested
python3 -c "
import chromadb
c = chromadb.PersistentClient('data/chroma')
col = c.get_collection('dataroom')
print(f'ChromaDB: {col.count()} chunks OK')
"

# Roles must have Anna + Carrie
python3 -c "
import json
r = json.load(open('data/roles.json'))
print('Users:', list(r['users'].values()))
"

# Alerts should exist
ls data/alerts/
```

---

## What This Is

MergeOps is a multi-agent M&A IT integration system for Northstar Technologies (acquirer)
and Orbit Systems (acquired). It runs entirely locally on a Dell Pro Max with GB10.
All LLM inference via NIM (NVIDIA Inference Microservices). No cloud calls at runtime.

Slack bot receives commands → LLM decides which tools to call → pipeline analyzes
transcripts → conflicts flagged → dual approval required → OpenShell releases execution.

---

## Scaffold Provided (Do Not Rewrite)

```
data/
  cleanroom/        ← CSV files: northstar_users.csv, orbit_users.csv
  chroma/           ← ChromaDB already ingested (contracts, policies, configs)
  dataroom/         ← Source documents (contracts, migration plan, etc.)
  decisions/        ← Written at runtime by pipeline.py
  alerts/           ← Pre-existing alerts (CW-001, DT-001)
  roles.json        ← Identity registry (Anna + Carrie)
  audit/            ← Written at runtime

scripts/
  prompts.py        ← All LLM prompts (DO NOT modify)
  identity.py       ← Identity resolution (DO NOT modify)
  data_cleanroom.py ← Clean room validation (DO NOT modify)

requirements.txt    ← chromadb, flask, requests, slack-bolt, python-dotenv, pyaudio
.env                ← SLACK_BOT_TOKEN, SLACK_APP_TOKEN, SLACK_WEBHOOK_URL, MERGEOPS_MODEL
```

---

## Files to Build Today

1. `scripts/slack_bot.py`         — Slack Socket Mode bot, agentic tool-calling
2. `scripts/pipeline.py`          — extract_claims → detect_conflicts → write decision
3. `scripts/approval_server.py`   — Flask UI :3000, dual approval
4. `scripts/post_approval_handler.py` — watches for APPROVED decisions, generates action items
5. `scripts/openShell_client.py`  — wraps NemoClaw/OpenShell CLI with local fallback
6. `scripts/war_room_server.py`   — Flask :3001, real-time meeting intelligence UI
7. `scripts/asr_stream.py`        — mic → Nemotron ASR NIM → War Room
8. `scripts/data_watcher.py`      — watches CSV files, Slack alert on change
9. `start.sh`                     — starts all services

---

## LLM Call Pattern (NIM — use this, not Ollama)

```python
import os, requests, json

NIM_URL = os.environ.get("NIM_LLM_URL", "http://localhost:8000/v1/chat/completions")
MODEL   = os.environ.get("MERGEOPS_MODEL", "qwen3-32b-dgx-spark")

def call_llm(system: str, user: str) -> dict:
    resp = requests.post(
        NIM_URL,
        headers={"Authorization": f"Bearer {os.environ.get('NGC_API_KEY', 'local')}"},
        json={
            "model": MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "temperature": 0,
        },
        timeout=120,
    )
    resp.raise_for_status()
    content = resp.json()["choices"][0]["message"]["content"]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {}
```

**Fallback to Ollama** if NIM not available (do not spend >15 min debugging NIM):
```python
# .env: set OLLAMA_URL=http://localhost:11434/api/chat, comment out NIM_LLM_URL
# In code:
NIM_URL    = os.environ.get("NIM_LLM_URL", "")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
USE_NIM    = bool(NIM_URL)

def call_llm(system, user):
    if USE_NIM:
        resp = requests.post(NIM_URL, headers={"Authorization": "Bearer local"},
                             json={"model": MODEL, "messages": [...], "temperature": 0})
        return json.loads(resp.json()["choices"][0]["message"]["content"])
    else:
        resp = requests.post(OLLAMA_URL,
                             json={"model": MODEL, "messages": [...], "stream": False,
                                   "format": "json", "options": {"temperature": 0}})
        return json.loads(resp.json()["message"]["content"])
```

---

## Tool-Calling Pattern (slack_bot.py agentic loop)

```python
# NIM tool calling — same as OpenAI format
def call_llm_with_tools(messages, tools):
    resp = requests.post(
        NIM_URL,
        headers={"Authorization": f"Bearer {os.environ.get('NGC_API_KEY', 'local')}"},
        json={"model": MODEL, "messages": messages, "tools": tools,
              "tool_choice": "auto", "temperature": 0},
        timeout=60,
    )
    return resp.json()["choices"][0]["message"]

# Agentic loop (max 6 steps)
messages = [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_text}]
for step in range(6):
    msg = call_llm_with_tools(messages, TOOLS)
    messages.append(msg)
    tool_calls = msg.get("tool_calls") or []
    if not tool_calls:
        say(msg.get("content", ""))
        return
    for tc in tool_calls:
        fn_name = tc["function"]["name"]
        fn_args = json.loads(tc["function"]["arguments"])
        result  = dispatch(fn_name, fn_args, ctx)
        messages.append({"role": "tool", "content": json.dumps(result)})
```

---

## 6 Tools for slack_bot.py

```python
TOOLS = [
    {"type": "function", "function": {
        "name": "get_my_identity",
        "description": "Get the identity of the user who sent this message.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "lookup_user",
        "description": "Look up any team member by name or Slack user ID.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "Name or Slack ID"}
        }, "required": ["query"]},
    }},
    {"type": "function", "function": {
        "name": "run_cleanroom",
        "description": "Run Data Clean Room: cross-reference Northstar + Orbit datasets locally.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "analyze_transcript",
        "description": "Analyze meeting transcript for M&A conflicts, create decision records.",
        "parameters": {"type": "object", "properties": {
            "text": {"type": "string", "description": "Transcript text to analyze"}
        }},
    }},
    {"type": "function", "function": {
        "name": "get_status",
        "description": "Get pending decisions and active risk alerts.",
        "parameters": {"type": "object", "properties": {}},
    }},
    {"type": "function", "function": {
        "name": "get_alerts",
        "description": "List all active risk alerts from Contract Watch and Dependency Tracker.",
        "parameters": {"type": "object", "properties": {}},
    }},
]
```

---

## Identity System

`data/roles.json` structure:
```json
{
  "users": {
    "U0C675Y48CR": {
      "name": "Anna Huang",
      "company": "northstar",
      "title": "Integration Lead",
      "display_title": "Northstar Integration Lead",
      "can_approve": true
    },
    "U0C6391DRHU": {
      "name": "Carrie Chen",
      "company": "orbit",
      "title": "IT Director",
      "display_title": "Orbit IT Director",
      "can_approve": true
    }
  },
  "companies": {
    "northstar": {"name": "Northstar Technologies", "emoji": ":large_blue_circle:"},
    "orbit":     {"name": "Orbit Systems",          "emoji": ":large_orange_circle:"}
  }
}
```

`identity.py` exports (already built — import and use):
```python
from identity import identify, find_by_name, greeting

identify("U0C675Y48CR")   # → {known: True, name: "Anna Huang", company: "northstar", ...}
find_by_name("carrie")    # → ("U0C6391DRHU", {user dict})
```

---

## Pipeline Flow

```
transcript (str)
    ↓  extract_claims()  — calls LLM with EXTRACT_CLAIMS_SYSTEM/USER prompts
claims: list[dict]       — each has: claim_id, action, target_system, scope, etc.
    ↓  search_dataroom() — ChromaDB similarity search on data/chroma
doc_chunks + alerts
    ↓  detect_conflicts() — calls LLM with DETECT_CONFLICTS_SYSTEM/USER prompts
conflicts: list[dict]    — each has: conflict_id, conflict_type, severity, source_document
    ↓  write_decision_record()
data/decisions/{ID}.json — decision record with status=PENDING_APPROVAL
    ↓  block_execution()  — OpenShell blocks until approved
    ↓  slack_notify()     — webhook message
```

**Decision record schema** (written to `data/decisions/{ID}.json`):
```json
{
  "decision_id": "DA3F9B",
  "status": "PENDING_APPROVAL",
  "created_at": "2026-10-03T10:00:00Z",
  "claim": {
    "claim_id": "C001",
    "action": "migrate",
    "target_system": "Orbit EU users",
    "scope": "all EU users",
    "destination": "Northstar US environment",
    "timeline": "next week",
    "raw_quote": "let's move all the Orbit EU users to the US environment next week"
  },
  "conflicts": [
    {
      "conflict_id": "CF001",
      "conflict_type": "GDPR_VIOLATION",
      "severity": "CRITICAL",
      "source_document": "orbit_data_policy.txt",
      "evidence_quote": "EU PII must remain in EU jurisdiction...",
      "explanation": "Moving EU user data to US violates GDPR data residency requirements",
      "blocks_execution": true
    }
  ],
  "critical_count": 1,
  "required_approvals": ["northstar", "orbit"],
  "received_approvals": {},
  "approved_by": null,
  "approved_at": null,
  "approved_option": null
}
```

---

## Approval Server (Flask :3000)

**Endpoints:**
- `GET /`                           → serve HTML UI (single-page, polls /api/decisions)
- `GET /api/decisions`              → return list of all decision records
- `POST /api/approve/<decision_id>` → body: `{option, company}` — record partial or full approval
- `POST /api/reject/<decision_id>`  → mark rejected

**Approval logic:**
```python
record["received_approvals"][company] = {"option": option, "approved_at": now}
required = set(record["required_approvals"])   # ["northstar", "orbit"]
received = set(record["received_approvals"].keys())
if required <= received:
    record["status"] = "APPROVED"
    # post_approval_handler.py will pick this up (polls every 5s)
```

**UI must show:**
- Decision ID, action, target, raw quote
- Each conflict (severity color: CRITICAL=red, WARNING=yellow)
- Per-company approve buttons (Northstar blue, Orbit orange)
- Approval status per company (✅ done / ⏳ pending)
- Auto-refresh every 3s (`setInterval(load, 3000)`)

---

## OpenShell Client (openShell_client.py)

Two functions needed:
```python
block_execution(decision_id, reason, action)
    # Try: nemoclaw shell block --id {id} --reason {reason} --action {action}
    # Fallback: write to data/audit/openShell_blocks.json

unblock_and_execute(decision_id, approved_option, action_items)
    # Try: nemoclaw shell execute --id {id} --approved-option {option}
    # Fallback: update data/audit/openShell_blocks.json status=RELEASED
    # Always: write to data/audit/log.jsonl
```

Pattern for nemoclaw subprocess call:
```python
import subprocess
result = subprocess.run(
    ["nemoclaw", "shell", "block", "--id", decision_id, "--reason", reason],
    capture_output=True, text=True, timeout=10
)
if result.returncode != 0:
    # fallback to local file
```

---

## War Room Server (war_room_server.py) — Flask :3001

**session.json** at `data/meeting/session.json`:
```json
{
  "session_id": "M-20261003-001",
  "status": "ACTIVE",
  "started_at": "2026-10-03T10:00:00Z",
  "transcript": [{"t": "10:32", "text": "...", "speaker": "unknown"}],
  "issues": [{"severity": "CRITICAL", "type": "GDPR_VIOLATION", "detected_at": "10:32",
              "decision_id": "D001", "text": "EU PII cannot move to us-east-1"}],
  "action_items": [{"id": "AI-001", "action": "...", "owner": "Legal",
                    "deadline_days": 7, "priority": "URGENT"}],
  "decisions": [{"decision_id": "D001", "action": "migrate", "target": "Orbit EU users",
                 "critical_conflicts": 2, "status": "PENDING_APPROVAL"}],
  "risk_score": 85
}
```

**Endpoints:**
```
GET  /api/meeting          → return session.json
POST /api/meeting/start    → create new session, status=ACTIVE
POST /api/meeting/end      → run full pipeline on transcript, send Slack summary
POST /api/meeting/chunk    → {"text": "...", "timestamp": "10:33"}
                             append to transcript, run extract_claims → detect_conflicts inline
                             recalculate risk_score, return updated session
```

**Risk score:**
```python
def calculate_risk_score(issues):
    score = sum(30 if i["severity"] == "CRITICAL" else 10 for i in issues)
    return min(score, 100)
```

**War Room UI layout:**
```
┌─ MergeOps War Room ─────────────────── LIVE ● 00:12:34 ─┐
│  LIVE TRANSCRIPT         │  RISK MONITOR                  │
│  10:32 "let's move EU    │  Risk Score  ████████░░ 85/100 │
│  users to US env..."     │  🔴 GDPR VIOLATION             │
│  10:33 "disable Okta"    │  🔴 CONTRACT BREACH            │
│                          │  Decisions pending: 2          │
├──────────────────────────┴────────────────────────────────┤
│  ACTION ITEMS                                             │
│  ☐ File DTIA approval   Legal   URGENT                   │
└────────────────────────────── [End Meeting ⏹] ───────────┘
```

**JS polling:**
```javascript
async function poll() {
  const s = await fetch('/api/meeting').then(r => r.json());
  updateTranscript(s.transcript);
  updateRiskCards(s.issues);
  document.getElementById('risk-score').textContent = s.risk_score;
  updateActionItems(s.action_items);
}
setInterval(poll, 1000);
```

**On End Meeting:**
```python
@app.route('/api/meeting/end', methods=['POST'])
def end_meeting():
    session['status'] = 'ANALYZING'
    full_text = ' '.join(t['text'] for t in session['transcript'])
    decisions = pipeline.run(full_text)   # full pipeline run
    session['status'] = 'COMPLETE'
    save_session(session)
    send_slack_summary(session, decisions)
    return jsonify(session)
```

Slack summary format:
```
📋 *MergeOps — Meeting Analysis Complete*
Session: M-20261003-001 | Duration: 00:23:47
*2 decisions require approval:*
  🔴 `D001` — MIGRATE Orbit EU users (2 critical conflicts)
🔒 OpenShell has blocked execution pending approval.
👉 Review: http://localhost:3000
```

---

## ASR Stream (asr_stream.py)

```python
import pyaudio, requests

CHUNK_SIZE  = 1024
SAMPLE_RATE = 16000
ASR_URL     = "http://localhost:5001/v1/audio/transcriptions"
WARROOM_URL = "http://localhost:3001/api/meeting/chunk"

p = pyaudio.PyAudio()
stream = p.open(format=pyaudio.paInt16, channels=1,
                rate=SAMPLE_RATE, input=True,
                frames_per_buffer=CHUNK_SIZE)
buffer = []
while True:
    data = stream.read(CHUNK_SIZE, exception_on_overflow=False)
    buffer.append(data)
    if len(buffer) >= (SAMPLE_RATE * 3 // CHUNK_SIZE):  # every ~3 seconds
        audio = b"".join(buffer); buffer = []
        resp = requests.post(ASR_URL,
                             files={"file": ("audio.wav", audio)},
                             data={"model": "nemotron-asr"}, timeout=10)
        if resp.ok:
            text = resp.json().get("text", "").strip()
            if text:
                requests.post(WARROOM_URL, json={"text": text}, timeout=5)
```

**Fallback (no mic / ASR not working):**
```bash
curl -X POST http://localhost:3001/api/meeting/chunk \
  -H "Content-Type: application/json" \
  -d '{"text": "let'\''s move all the Orbit EU users to the US environment"}'
```

---

## Data Watcher (data_watcher.py)

```python
import hashlib, time, requests
from pathlib import Path

WATCH_FILES = [Path("data/cleanroom/northstar_users.csv"),
               Path("data/cleanroom/orbit_users.csv")]
SLACK_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")
REPORT_INTERVAL = 4 * 3600

def file_hash(path):
    return hashlib.md5(path.read_bytes()).hexdigest() if path.exists() else ""

hashes = {f: file_hash(f) for f in WATCH_FILES}
last_report = time.time()
while True:
    time.sleep(60)
    changed = [f for f in WATCH_FILES if file_hash(f) != hashes[f]]
    for f in changed:
        hashes[f] = file_hash(f)
    if changed or time.time() - last_report > REPORT_INTERVAL:
        # run cleanroom + post to Slack
        from data_cleanroom import run_validation, format_slack_summary
        findings = run_validation()
        prefix = ":warning: *Data Change Detected*\n" if changed else ":white_check_mark: *Scheduled Report*\n"
        requests.post(SLACK_WEBHOOK, json={"text": prefix + format_slack_summary(findings, "")})
        last_report = time.time()
```

---

## start.sh

```bash
#!/bin/bash
set -e
export PYTHONUNBUFFERED=1
cd "$(dirname "$0")"

# Kill stale processes
pkill -f "slack_bot.py" 2>/dev/null || true
pkill -f "approval_server.py" 2>/dev/null || true
pkill -f "post_approval_handler.py" 2>/dev/null || true
pkill -f "war_room_server.py" 2>/dev/null || true
pkill -f "data_watcher.py" 2>/dev/null || true
sleep 1

# Clear logs
mkdir -p logs
: > logs/slack_bot.log
: > logs/approval.log
: > logs/post_approval.log
: > logs/war_room.log
: > logs/data_watcher.log

# Start services
PYTHONUNBUFFERED=1 python -u scripts/slack_bot.py > logs/slack_bot.log 2>&1 &
echo "Slack bot PID: $!"

PYTHONUNBUFFERED=1 python -u scripts/approval_server.py > logs/approval.log 2>&1 &
echo "Approval server PID: $!"

PYTHONUNBUFFERED=1 python -u scripts/post_approval_handler.py --watch > logs/post_approval.log 2>&1 &
echo "Post-approval handler PID: $!"

PYTHONUNBUFFERED=1 python -u scripts/war_room_server.py > logs/war_room.log 2>&1 &
echo "War Room PID: $!"

PYTHONUNBUFFERED=1 python -u scripts/data_watcher.py > logs/data_watcher.log 2>&1 &
echo "Data Watcher PID: $!"

echo ""
echo "MergeOps started."
echo "  Slack bot:    logs/slack_bot.log"
echo "  Approval UI:  http://localhost:3000"
echo "  War Room:     http://localhost:3001"
echo ""
echo "Tailing logs (Ctrl+C to stop tailing — services keep running):"
tail -f logs/*.log
```

---

## .env Template

The `.env` file is included in the scaffold — Slack tokens are already set.
Only add the NIM lines after starting containers:

```
# Already in scaffold — do not change
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
APPROVAL_UI_URL=http://localhost:3000

# Add / uncomment after NIM containers are running
MERGEOPS_MODEL=qwen3-32b-dgx-spark
NIM_LLM_URL=http://localhost:8000/v1/chat/completions
NIM_ASR_URL=http://localhost:5001/v1/audio/transcriptions

# Fallback: comment out NIM_LLM_URL and use these instead
# MERGEOPS_MODEL=qwen2.5:7b
# OLLAMA_URL=http://localhost:11434/api/chat
```

---

## NIM Containers (load from SSD)

```bash
SSD="/mnt/ssd"   # confirm actual path on GB10

for f in $SSD/mergeops/nim/*.tar.gz; do
    echo "Loading $f..."
    docker load < $f
done

# Start containers
docker run --gpus all -d -p 8000:8000 nvcr.io/nim/qwen/qwen3-32b-dgx-spark:latest
docker run --gpus all -d -p 5001:8000 nvcr.io/nim/nvidia/nemotron-asr-streaming:1.3.1
docker run --gpus all -d -p 5002:8000 nvcr.io/nim/nvidia/nemotron-3-embed-1b:latest

# Verify
curl http://localhost:8000/v1/models
```

---

## Port Map

| Service | Port |
|---|---|
| NIM Primary LLM | 8000 |
| Nemotron ASR | 5001 |
| Nemotron Embed | 5002 |
| Approval UI | 3000 |
| War Room | 3001 |
| Ollama (fallback) | 11434 |

---

## Demo Script (10 min)

1. `bash start.sh`
2. Open War Room: http://localhost:3001
3. Open Approval: http://localhost:3000
4. **@Meridian status** → Slack confirms alive
5. War Room: click Start Meeting
6. Speak / inject: *"Let's move all the Orbit EU users to the Northstar US environment next week"*
7. Watch: GDPR card appears, risk score rises
8. Speak: *"And we should disable the Orbit Okta instance once migration is done"*
9. Watch: CONTRACT BREACH card, risk score 85
10. Click End Meeting → decisions pushed to Approval UI
11. Anna approves as Northstar → Carrie approves as Orbit
12. Watch: OpenShell releases block, action items generated, Slack notification sent
13. Edit `northstar_users.csv` → within 60s DataWatcher fires Slack alert
14. **@Meridian who is Carrie** → identity lookup demo

---

## Key Gotchas

- **Python stdout buffering**: always add at top of every script:
  ```python
  sys.stdout = open(sys.stdout.fileno(), mode='w', buffering=1, closefd=False)
  ```
- **ChromaDB**: `data/chroma/` already has embeddings — do NOT re-ingest
- **load_decisions()**: skip `_actions.json` files, only load records with `decision_id` AND `conflicts`
- **DrvFs (Windows SSD)**: no Unix file locks, no chmod — download HF models to Linux home first, then `mv`
- **NIM tool_calls format**: same as OpenAI — `tc["function"]["name"]`, `json.loads(tc["function"]["arguments"])`
- **Slack Socket Mode**: uses `SLACK_APP_TOKEN` (xapp-), not bot token, for the WebSocket connection
