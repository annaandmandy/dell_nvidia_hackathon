#!/usr/bin/env python3
"""
Meridian Slack channel bot.

Uses Slack Socket Mode for the hackathon interaction surface. Policy and
financial calculations stay in app.py; Slack is only a transport.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from typing import Any

import requests
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from app import Context, handle_request
from meridian_format import format_response

load_dotenv()

BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
APP_TOKEN = os.environ.get("SLACK_APP_TOKEN", "")
WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")


def csv_set(name: str) -> set[str]:
    return {x.strip() for x in os.environ.get(name, "").split(",") if x.strip()}


A_USER_IDS = csv_set("MERIDIAN_A_USER_IDS")
B_USER_IDS = csv_set("MERIDIAN_B_USER_IDS")
A_DM_CHANNEL_IDS = csv_set("MERIDIAN_A_DM_CHANNEL_IDS")
B_DM_CHANNEL_IDS = csv_set("MERIDIAN_B_DM_CHANNEL_IDS")
JOINT_CHANNEL_IDS = csv_set("MERIDIAN_JOINT_CHANNEL_IDS")


def require_tokens() -> None:
    missing = []
    if not BOT_TOKEN:
        missing.append("SLACK_BOT_TOKEN")
    if not APP_TOKEN:
        missing.append("SLACK_APP_TOKEN")
    if missing:
        raise SystemExit(f"Missing required Slack env vars: {', '.join(missing)}")


def strip_bot_mention(text: str) -> str:
    return re.sub(r"<@[A-Z0-9]+>\s*", "", text or "").strip()


def infer_context(event: dict[str, Any]) -> Context:
    user_id = event.get("user") or "unknown-user"
    channel_id = event.get("channel") or "unknown-channel"
    channel_type_raw = event.get("channel_type") or ""

    if user_id in A_USER_IDS or channel_id in A_DM_CHANNEL_IDS:
        organization = "A"
    elif user_id in B_USER_IDS or channel_id in B_DM_CHANNEL_IDS:
        organization = "B"
    else:
        organization = "NEUTRAL"

    if channel_type_raw == "im":
        if organization == "A":
            channel_type = "A_DM"
        elif organization == "B":
            channel_type = "B_DM"
        else:
            channel_type = "JOINT_SLACK"
    else:
        channel_type = "JOINT_SLACK"

    return Context(
        actor_id=user_id,
        organization=organization,
        channel_type=channel_type,
        session_id=channel_id,
    )


def build_slack_app() -> App:
    require_tokens()
    slack_app = App(token=BOT_TOKEN)

    @slack_app.event("app_mention")
    def on_app_mention(event, say):
        text = strip_bot_mention(event.get("text", ""))
        ctx = infer_context(event)
        result = handle_request(text, ctx)
        say(format_response(result))

    @slack_app.event("message")
    def on_message(event, say):
        if event.get("bot_id") or event.get("subtype"):
            return
        if event.get("channel_type") != "im":
            return
        text = strip_bot_mention(event.get("text", ""))
        if not text:
            return
        ctx = infer_context(event)
        result = handle_request(text, ctx)
        say(format_response(result))

    return slack_app


def post_webhook_smoke() -> None:
    if not WEBHOOK_URL:
        raise SystemExit("SLACK_WEBHOOK_URL is not configured.")
    msg = {
        "text": (
            "*Meridian smoke test*\n"
            "Slack transport is configured. Socket Mode bot can now handle app mentions and DMs."
        )
    }
    resp = requests.post(WEBHOOK_URL, json=msg, timeout=10)
    resp.raise_for_status()
    print("Webhook smoke message sent.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-webhook", action="store_true", help="Send one webhook test message and exit.")
    parser.add_argument("--print-config", action="store_true", help="Print non-secret runtime config.")
    args = parser.parse_args()

    if args.print_config:
        print(json.dumps({
            "bot_token_configured": bool(BOT_TOKEN),
            "app_token_configured": bool(APP_TOKEN),
            "webhook_configured": bool(WEBHOOK_URL),
            "a_user_ids": sorted(A_USER_IDS),
            "b_user_ids": sorted(B_USER_IDS),
            "joint_channel_ids": sorted(JOINT_CHANNEL_IDS),
        }, indent=2))
        return

    if args.smoke_webhook:
        post_webhook_smoke()
        return

    print("Meridian Slack bot starting in Socket Mode...")
    slack_app = build_slack_app()
    SocketModeHandler(slack_app, APP_TOKEN).start()


if __name__ == "__main__":
    main()
