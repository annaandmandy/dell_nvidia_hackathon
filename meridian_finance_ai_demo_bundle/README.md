# Meridian Financial Services × AI Acquisition Demo

This synthetic bundle supports an eight-minute demo of a neutral third-party agent in the proposed acquisition of QuantaShield AI by HarborStone Financial Group.

Start with:

1. `DEMO_RUNBOOK_CN.md` — live presenter script.
2. `CODE_AGENT_CONTEXT.md` — complete implementation context.
3. `AGENT_SYSTEM_PROMPT.md` — runtime behavioral prompt.
4. `analysis/QuantaShield_Acquisition_Diligence.xlsx` — deterministic deal model.
5. `demo_documents/` — material to pull during meeting and camera flows.
6. `data/attack_tests.json` — security cases.
7. `scripts/` — signature and expected-result checks.

Data zones:

- `data/private_a`: HarborStone-only data.
- `data/private_b`: QuantaShield-only data.
- `data/clean_room`: raw inputs allowed only in approved calculations.
- `data/joint_approved`: summaries both sides approved.
- `signed_inputs`: signed release payloads and one tampered attack fixture.
- `demo_keys`: demo-only Ed25519 keys; never use in production.

All names, figures, documents and findings are fictional and created for this demo.
