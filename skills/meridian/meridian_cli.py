#!/usr/bin/env python3
"""
OpenClaw entry point for Meridian (Carrie's app.py), run inside the NemoClaw sandbox.

  python3 meridian_cli.py --sender U0C675Y48CR --dm "calculate combined 2025 revenue"
  python3 meridian_cli.py --sender U0C6391DRHU --channel "is 96m fair?"

Access decisions stay deterministic in app.py. Organization comes from the sender's
company "org" in roles.json (HarborStone -> A buyer, QuantaShield -> B target),
mirroring slack_bot.infer_context. No LLM call here: OpenClaw's own local model words the reply.
"""
import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ["MERIDIAN_LLM_URL"] = "disabled"  # llm_polish -> deterministic fallback
os.environ.pop("OPENAI_API_KEY", None)
sys.path.insert(0, str(HERE))

from app import (Context, format_criteria_response, format_criteria_table, handle_request,  # noqa: E402
                 is_show_visual_criteria_command, is_visual_criteria_command)
from meridian_format import format_response  # noqa: E402

# Visual-audit criteria live in app.py on the host (the /vision page reads them), reached through
# the meridian-host OpenShell policy. Parsing happens host-side, so both sides agree.
HOST_API = os.environ.get("MERIDIAN_HOST_API", "http://host.openshell.internal:5050")


NEW_ROOM_PHRASES = ("new deal", "start a new deal", "new demo", "reset the demo", "open a deal room")
MEETING_PHRASES = ("new meeting", "start meeting", "start the meeting", "start a meeting", "open the meeting", "open a meeting")


def is_command(question: str, phrases: tuple[str, ...]) -> bool:
    """Only a message that *starts* with the phrase triggers it ('what is the new meeting time?' does not)."""
    q = question.lower().strip(" .!?")
    for prefix in ("please ", "let's ", "lets ", "meridian, ", "meridian "):
        q = q.removeprefix(prefix)
    return any(q.startswith(p) for p in phrases)


def host_post(path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(f"{HOST_API}{path}", data=json.dumps(body or {}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def host_criteria(text: str | None = None) -> list[dict]:
    data = None if text is None else json.dumps({"text": text}).encode()
    req = urllib.request.Request(f"{HOST_API}/api/visual-criteria", data=data,
                                 headers={"Content-Type": "application/json"}, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())["criteria"]


def infer_context(sender: str, is_dm: bool) -> Context:
    roles = json.loads((HERE / "roles.json").read_text())
    company = roles["users"].get(sender, {}).get("company")
    organization = roles["companies"].get(company, {}).get("org", "NEUTRAL")
    if is_dm and organization in ("A", "B"):
        channel_type = f"{organization}_DM"
    else:
        channel_type = "JOINT_SLACK"
    return Context(actor_id=sender, organization=organization, channel_type=channel_type, session_id="openclaw")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sender", required=True, help="Slack user ID of the message sender")
    where = p.add_mutually_exclusive_group(required=True)
    where.add_argument("--dm", action="store_true", help="message came from a direct message")
    where.add_argument("--channel", action="store_true", help="message came from a shared channel")
    where.add_argument("--camera", action="store_true", help="question is a card marker read by the vision model")
    p.add_argument("question", nargs="+")
    args = p.parse_args()

    question = " ".join(args.question)
    if is_command(question, NEW_ROOM_PHRASES):
        room = host_post("/api/deal-room/reset", {"announce": False, "actor_id": args.sender})
        print(f"*Meridian* — `ALLOW` / `DEAL_ROOM_OPENED`\n{room['announcement']}")
        return
    if is_command(question, MEETING_PHRASES):
        room = host_post("/api/room/start", {"announce": False, "actor_id": args.sender})
        print(f"*Meridian* — `ALLOW` / `MEETING_STARTED`\n{room['announcement']}")
        return
    if is_visual_criteria_command(question):
        print(format_criteria_response(host_criteria(question)))
        return
    if is_show_visual_criteria_command(question):
        print("*Current Meridian visual audit criteria:*\n" + format_criteria_table(host_criteria()))
        return

    ctx = infer_context(args.sender, args.dm)
    if args.camera:
        ctx = Context(actor_id=args.sender, organization="NEUTRAL", channel_type="CAMERA", session_id="openclaw")
    result = handle_request(question, ctx)
    if result["reason_code"] == "ALLOW_OWNER_AUTHORIZED_DISCLOSURE":
        # The owner released it here; the host re-checks identity and posts it to the joint channel.
        published = host_post("/api/owner-disclosure", {"sender": args.sender, "dm": args.dm, "text": question})
        result["answer"] += (" Posted to the joint channel for the other party." if published.get("ok")
                             else " (Could not post to the joint channel.)")
    print(format_response(result))
    print(f"\n_context: org={ctx.organization} channel={ctx.channel_type}_")


if __name__ == "__main__":
    main()
