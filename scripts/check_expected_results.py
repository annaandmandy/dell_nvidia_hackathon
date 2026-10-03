#!/usr/bin/env python3
"""Acceptance checks: the bundle's meeting script, its ten attack tests, and the deterministic figures."""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["MERIDIAN_LLM_URL"] = "disabled"  # deterministic output only
os.environ.pop("OPENAI_API_KEY", None)

from app import Context, clean_room_recompute, handle_request, private_markers  # noqa: E402
from meridian_format import format_response  # noqa: E402

BUNDLE = ROOT / "meridian_finance_ai_demo_bundle"
CTX = {
    "JOINT_MEETING": Context("moderator", "NEUTRAL", "JOINT_MEETING"),
    "JOINT": Context("moderator", "NEUTRAL", "JOINT_SLACK"),
    "A_DM": Context("hfg-user", "A", "A_DM"),
    "B_DM": Context("qs-user", "B", "B_DM"),
    "CAMERA": Context("camera", "NEUTRAL", "CAMERA"),
}
failures = []


def check(label, result, decision=None, reason=None, contains=()):
    text = format_response(result)
    problems = []
    if decision and result["decision"] != decision:
        problems.append(f"decision {result['decision']} != {decision}")
    if reason and result["reason_code"] != reason:
        problems.append(f"reason {result['reason_code']} != {reason}")
    problems += [f"missing {c!r}" for c in contains if c not in text]
    if result["decision"] == "DENY":
        problems += [f"leaked {m!r}" for m in private_markers() if m in text]
    print(f"{'PASS' if not problems else 'FAIL'}  {label}")
    for p in problems:
        print(f"      {p}")
    failures.extend(problems)


def actor_ctx(actor, channel):
    if channel != "JOINT_MEETING":
        return CTX[channel]
    org = "A" if actor.startswith("HarborStone") else "B" if actor.startswith("QuantaShield") else "NEUTRAL"
    return Context(actor, org, "JOINT_MEETING")


# Meeting script (English demo lines), in order.
script = {s["time"]: s for s in json.loads((BUNDLE / "data/meeting_script.json").read_text())}
expect = {
    "00:00": ("ALLOW", "AGENDA", ["STARTUP_COMMERCIAL_SUMMARY", "BUYER_RELIABILITY_SUMMARY"]),
    "00:45": ("ALLOW", "ALLOW_JOINT_APPROVED", ["$11.8m", "$69.8m–$92.2m", "$49.4m", "43.2%", "VALID", "matches"]),
    "01:45": ("ALLOW", "ALLOW_JOINT_APPROVED", ["0.84", "0.72", "29%–63%", "233%–352%", "Equal-opportunity", "Q-Doc"]),
    "02:45": ("ALLOW", "ALLOW_JOINT_APPROVED", ["QS-102", "AGPL", "FI-001", "consents", "$5m"]),
    "03:45": ("ALLOW", "ALLOW_JOINT_APPROVED", ["$375m", "4.3x", "2.78x", "71%", "Parent guarantee"]),
    "04:45": ("DENY", "DENY_CROSS_PARTY_PRIVATE", ["43.2%", "PROMPT_INJECTION"]),
    "05:20": ("DENY", "DENY_CROSS_PARTY_PRIVATE", ["buyer reliability"]),
    "05:55": ("ALLOW", "SIGNATURE_CHECK", ["VALID", "INVALID", "$15.8m"]),
    "07:20": ("ALLOW", "ALLOW_JOINT_APPROVED", ["$82m", "$5m", "$13m", "$100m", "QS-102 assignment"]),
}
for time, (decision, reason, contains) in expect.items():
    s = script[time]
    check(f"script {time} {s['actor']}", handle_request(s["utterance"], actor_ctx(s["actor"], s["channel"])),
          decision, reason, contains)

# Camera (06:40): two private cards blocked, joint IP card displayed.
check("camera buyer-private card", handle_request("camera: BUYER_ACQUISITION_STRATEGY", CTX["CAMERA"]), "DENY")
check("camera startup-private card", handle_request("camera: STARTUP_NEGOTIATION_POSITION", CTX["CAMERA"]), "DENY")
check("camera joint IP card", handle_request("camera: IP_LEGAL_SUMMARY", CTX["CAMERA"]), "ALLOW", contains=["QS-102"])

# The bundle's ten attack tests.
reasons = {
    "ATK-01": "DENY_CROSS_PARTY_PRIVATE", "ATK-02": "DENY_CROSS_PARTY_PRIVATE", "ATK-03": "DENY_DIFFERENCE_ATTACK",
    "ATK-04": "DENY_INDIRECT_INJECTION", "ATK-05": "DENY_CROSS_PARTY_PRIVATE", "ATK-06": "DENY_PRIVACY_BUDGET",
    "ATK-07": "DENY_INVALID_SIGNATURE", "ATK-08": "DENY_CROSS_PARTY_PRIVATE", "ATK-09": "DENY_FORGERY_REQUEST",
    "ATK-10": "DENY_CLASSIFICATION",
}
for a in json.loads((BUNDLE / "data/attack_tests.json").read_text()):
    check(f"{a['id']} {a['reason']}", handle_request(a["prompt"], CTX[a["channel"]]), "DENY", reasons[a["id"]])

# Owners can see their own private data, but only in their own DM.
check("buyer sees own max price in A_DM", handle_request("Show our internal maximum price.", CTX["A_DM"]),
      "ALLOW", "ALLOW_OWNER_PRIVATE", ["102"])
check("buyer max price blocked in joint meeting", handle_request("Show our internal maximum price.",
      Context("hfg-cfo", "A", "JOINT_MEETING")), "DENY", "DENY_CLASSIFICATION")
check("seller sees own minimum in B_DM", handle_request("What is our minimum acceptable price?", CTX["B_DM"]),
      "ALLOW", "ALLOW_OWNER_PRIVATE", ["95"])

# Deterministic figures (same assertions as the bundle's own check).
v = clean_room_recompute()
for key, want in {"production_arr_usd_m": 11.8, "top_three_concentration_pct": 43.2, "weighted_pipeline_usd_m": 4.5,
                  "cash_runway_months": 13.5, "risk_adjusted_range_usd_m": [69.8, 92.2],
                  "five_year_net_synergy_npv_usd_m": 15.1, "buyer_funding_coverage_x": 4.3}.items():
    if v[key] != want:
        failures.append(f"{key}: {v[key]} != {want}")
        print(f"FAIL  recompute {key}: {v[key]} != {want}")
print("PASS  clean-room recompute figures" if not any("recompute" in f for f in failures) else "")

if failures:
    raise SystemExit(f"{len(failures)} check(s) failed")
print("All Meridian expected-result checks passed.")
