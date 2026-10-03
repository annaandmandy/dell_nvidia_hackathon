# Data Dictionary

All monetary values are USD millions unless a field says otherwise. All files are synthetic.

## Classifications

| Value | Meaning |
| --- | --- |
| `PUBLIC` | approved for all demo users |
| `A_PRIVATE` | HarborStone only |
| `B_PRIVATE` | QuantaShield only |
| `JOINT_APPROVED` | explicitly approved for both parties |
| `CLEAN_ROOM` | raw input to approved calculations only |
| `AGENT_INTERNAL` | policies, keys, logs and infrastructure metadata |

## Buyer files

| File | Important fields | Use |
| --- | --- | --- |
| `buyer_financials.csv` | revenue, EBITDA, FCF, cash, debt, interest | credit and funding trend |
| `liquidity.csv` | amount, availability, condition | funding coverage |
| `debt_covenants.csv` | limit, current, pro forma | covenant headroom |
| `regulatory_matters.csv` | authority, topic, severity, status | counterparty risk |
| `acquisition_history.csv` | budget, actual, delay, retention | execution reliability |
| `acquisition_strategy.json` | offer, internal maximum, required conditions | buyer-only negotiation |

## Startup files

| File | Important fields | Use |
| --- | --- | --- |
| `startup_financials.csv` | revenue, ARR, margin, EBITDA, FCF, cash | growth, runway, forecast |
| `customer_arr.csv` | token, status, ARR, renewal, consent | concentration and retention |
| `sales_pipeline.csv` | stage, potential ARR, probability | weighted pipeline |
| `model_benchmarks.csv` | model, metric, baseline, validation | technical efficacy |
| `pilot_outcomes.csv` | benefit, fee, ROI, review reduction | customer economics |
| `patent_portfolio.csv` | asset, status, assignment, FTO | patent diligence |
| `open_source_inventory.csv` | license, network use, source availability | license compliance |
| `training_data_rights.csv` | source, personal data, training right | data provenance |
| `customer_contracts.csv` | consent, GLBA terms, training rights | contract diligence |
| `employee_ip_assignments.csv` | population, signed, incomplete | chain of title |
| `security_findings.csv` | domain, severity, status, cost | cyber remediation |
| `legal_matters.csv` | type, description, amount, status | legal contingencies |
| `negotiation_position.json` | request, floor, protections | seller-only negotiation |

## Calculation definitions

- `ARR growth = 2025 ending ARR / 2024 ending ARR - 1`.
- `weighted pipeline = Σ potential ARR × stage probability`.
- `top-three concentration = top three production customer ARR / ending ARR`.
- `cash runway = cash / assumed monthly cash burn`.
- `funding coverage = available cash + undrawn revolver + committed facility, divided by close cash + escrow`.
- `DCF terminal value = final forecast FCF × (1 + g) / (WACC - g)`.
- `risk-adjusted range = 25% ARR method + 50% forward-revenue method + 25% DCF`.
- `net synergy NPV = discounted synergy benefits - discounted integration costs`.

## Evidence flags

- `independent_validation`: whether a third party or customer validated the test.
- `signed_customer_confirmation`: whether customer economics are signed by the customer.
- `evidence_quality`: qualitative strength and known limitation.
- `risk`: issue-spotting priority, not a legal conclusion.
- `transaction_blocking`: synthetic management view, not legal advice.
