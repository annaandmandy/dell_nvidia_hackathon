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
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.environ["MERIDIAN_LLM_URL"] = "disabled"  # llm_polish -> deterministic fallback
os.environ.pop("OPENAI_API_KEY", None)
sys.path.insert(0, str(HERE))

from app import Context, handle_request  # noqa: E402
from meridian_format import format_response  # noqa: E402


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
    p.add_argument("question", nargs="+")
    args = p.parse_args()

    ctx = infer_context(args.sender, args.dm)
    result = handle_request(" ".join(args.question), ctx)
    print(format_response(result))
    print(f"\n_context: org={ctx.organization} channel={ctx.channel_type}_")


if __name__ == "__main__":
    main()
