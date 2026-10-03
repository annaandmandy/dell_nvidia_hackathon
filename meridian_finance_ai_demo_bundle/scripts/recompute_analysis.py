#!/usr/bin/env python3
"""Recompute the synthetic valuation, commercial and buyer-reliability outputs."""

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def rows(relative):
    with (ROOT / relative).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main():
    financials = {row["period"]: row for row in rows("data/private_b/startup_financials.csv")}
    customers = rows("data/private_b/customer_arr.csv")
    pipeline = rows("data/private_b/sales_pipeline.csv")
    synergies = rows("data/clean_room/synergy_assumptions.csv")
    liquidity = rows("data/private_a/liquidity.csv")

    arr = float(financials["2025A"]["ending_arr_usd_m"])
    forward_revenue = float(financials["2026E"]["revenue_usd_m"])
    arr_range = [arr * 5.5, arr * 7.5]
    revenue_range = [forward_revenue * 5.0, forward_revenue * 7.0]
    discount_rate, terminal_growth = 0.18, 0.035
    forecast_fcf = [-4.0, 0.5, 5.5, 9.0, 12.5]
    pv_forecast = sum(cf / (1 + discount_rate) ** year for year, cf in enumerate(forecast_fcf, 1))
    terminal = forecast_fcf[-1] * (1 + terminal_growth) / (discount_rate - terminal_growth)
    dcf = pv_forecast + terminal / (1 + discount_rate) ** 5
    weighted = [0.25 * arr_range[i] + 0.50 * revenue_range[i] + 0.25 * dcf for i in range(2)]

    steady = sum(float(row["steady_state_ebitda_usd_m"]) for row in synergies)
    ramp = [0.25, 0.60, 1.0, 1.0, 1.0]
    synergy_rate = 0.14
    benefits = sum(steady * pct / (1 + synergy_rate) ** year for year, pct in enumerate(ramp, 1))
    costs = 5.0 + 4.0 / 1.14 + 3.0 / 1.14**2

    production = [row for row in customers if row["status"] == "production"]
    production_arr = sorted((float(row["arr_usd_m"]) for row in production), reverse=True)
    weighted_pipeline = sum(float(row["potential_arr_usd_m"]) * float(row["probability"]) for row in pipeline)
    available_liquidity = sum(float(row["amount_usd_m"]) for row in liquidity if row["availability"] in {"available", "committed"})

    output = {
        "production_arr_usd_m": round(sum(production_arr), 1),
        "top_three_concentration_pct": round(100 * sum(production_arr[:3]) / arr, 1),
        "weighted_pipeline_usd_m": round(weighted_pipeline, 1),
        "cash_runway_months": round(float(financials["2025A"]["cash_usd_m"]) / 0.62, 1),
        "arr_method_usd_m": [round(x, 1) for x in arr_range],
        "forward_revenue_method_usd_m": [round(x, 1) for x in revenue_range],
        "dcf_enterprise_value_usd_m": round(dcf, 1),
        "risk_adjusted_range_usd_m": [round(x, 1) for x in weighted],
        "steady_state_synergy_usd_m": round(steady, 1),
        "five_year_net_synergy_npv_usd_m": round(benefits - costs, 1),
        "buyer_funding_coverage_x": round(available_liquidity / 87.0, 1),
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
