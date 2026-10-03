"""Slack-flavoured rendering of Meridian results (shared by slack_bot.py and the OpenClaw skill)."""
from __future__ import annotations

from typing import Any


def format_response(result: dict[str, Any]) -> str:
    lines = [
        f"*Meridian* — `{result.get('decision', '?')}` / `{result.get('reason_code', '?')}`",
        result.get("answer", ""),
    ]

    calc = result.get("calculated_results")
    if calc:
        lines += [
            "",
            "*Calculated results*",
            f"• Combined revenue: `${calc['combined_revenue_m']:.1f}m`",
            f"• Combined EBITDA: `${calc['combined_ebitda_m']:.1f}m`",
            f"• EBITDA margin: `{calc['combined_ebitda_margin_pct']:.1f}%`",
        ]

    assessment = result.get("neutral_assessment")
    if assessment:
        lines += [
            "",
            "*Neutral assessment facts*",
            f"• Standalone range: `${assessment['standalone_value_range_m'][0]}m-${assessment['standalone_value_range_m'][1]}m`",
            f"• Synergy NPV: `${assessment['five_year_net_synergy_npv_m']}m`",
            f"• Bridge: {assessment['recommendation']}",
            f"• {assessment['disclaimer']}",
        ]

    docs = result.get("retrieved_documents") or []
    if docs:
        lines += ["", "*Approved resources shown*"]
        for doc in docs[:8]:
            lines.append(f"• `{doc['resource_id']}` — {doc['title']} ({doc['classification']})")

    denied_docs = result.get("denied_documents") or []
    if denied_docs:
        lines += ["", "*Resources blocked by policy*"]
        for doc in denied_docs[:8]:
            lines.append(f"• `{doc['resource_id']}` — `{doc['reason_code']}`")

    signature = result.get("signature")
    if signature:
        lines += [
            "",
            "*Signature check*",
            f"• Resource: `{signature.get('resource_id')}`",
            f"• Status: `{signature.get('signature_status')}`",
            f"• Payload hash: `{signature.get('payload_hash')}`",
        ]

    return "\n".join(lines).strip()
