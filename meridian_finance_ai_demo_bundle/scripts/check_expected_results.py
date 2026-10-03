#!/usr/bin/env python3
"""Fast deterministic checks for figures, signatures and tamper detection."""

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True)


def main():
    result = run(sys.executable, "scripts/recompute_analysis.py")
    assert result.returncode == 0, result.stdout + result.stderr
    values = json.loads(result.stdout)
    assert values["production_arr_usd_m"] == 11.8
    assert values["top_three_concentration_pct"] == 43.2
    assert values["weighted_pipeline_usd_m"] == 4.5
    assert values["cash_runway_months"] == 13.5
    assert values["risk_adjusted_range_usd_m"] == [69.8, 92.2]
    assert values["five_year_net_synergy_npv_usd_m"] == 15.1
    assert values["buyer_funding_coverage_x"] == 4.3

    fixtures = [
        ("startup_commercial_authorized", "startup_commercial_authorized"),
        ("startup_ip_authorized", "startup_ip_authorized"),
        ("buyer_reliability_authorized", "buyer_reliability_authorized"),
        ("calculation_receipt", "calculation_receipt"),
    ]
    for payload, key in fixtures:
        check = run(sys.executable, "scripts/verify_signature.py", f"signed_inputs/{payload}.json", f"signed_inputs/{payload}.sig.b64", f"demo_keys/{key}_public.pem")
        assert check.returncode == 0, check.stdout + check.stderr

    tampered = run(sys.executable, "scripts/verify_signature.py", "signed_inputs/ATTACK_tampered_startup_metrics.json", "signed_inputs/startup_commercial_authorized.sig.b64", "demo_keys/startup_commercial_authorized_public.pem")
    assert tampered.returncode == 1, tampered.stdout + tampered.stderr
    print("PASS: calculations, valid signatures and tamper detection match the finance/AI acquisition design")


if __name__ == "__main__":
    main()
