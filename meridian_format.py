"""Slack-flavoured rendering of Meridian results (shared by slack_bot.py and the OpenClaw skill)."""
from __future__ import annotations

from typing import Any

LABEL_ICON = {
    "VERIFIED_FACT": ":white_check_mark:",
    "CALCULATED_RESULT": ":abacus:",
    "ASSUMPTION": ":memo:",
    "NEUTRAL_ASSESSMENT": ":scales:",
    "UNRESOLVED": ":warning:",
}


def format_response(result: dict[str, Any]) -> str:
    lines = [
        f"*Meridian* — `{result.get('decision', '?')}` / `{result.get('reason_code', '?')}`",
        result.get("answer", ""),
    ]

    for sec in result.get("sections") or []:
        icon = LABEL_ICON.get(sec["label"], "•")
        lines += ["", f"{icon} *{sec['title']}* `{sec['label']}`"]
        lines += [f"• {line}" for line in sec["lines"]]

    signatures = result.get("signatures") or []
    if signatures:
        lines += ["", ":lock: *Signature check (Ed25519)*"]
        for sig in signatures:
            mark = ":large_green_circle:" if sig["status"] == "VALID" else ":red_circle:"
            lines.append(f"{mark} `{sig['payload']}` — {sig['status']} (issuer: {sig['issuer']}, "
                         f"sha256 `{sig['payload_sha256'][:12]}…`)")

    if result.get("decision") == "DENY":
        if result.get("alternative"):
            lines += ["", f":arrow_right: {result['alternative']}"]
        events = [e for e in result.get("safety_events") or [] if e != result.get("reason_code")]
        if events:
            lines.append(f":rotating_light: Logged: `{'`, `'.join(events)}`")

    if result.get("disclaimer"):
        lines += ["", f"_{result['disclaimer']}_"]

    return "\n".join(lines).strip()
