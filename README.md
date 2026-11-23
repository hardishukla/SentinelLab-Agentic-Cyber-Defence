# SentinelLab — Agentic Cyber Defence & SOC Training Simulator

**Status:** Working educational portfolio prototype, November 2026. **Author/portfolio owner:** Hardi Shukla (extend, understand, and test before representing as your own engineering work).

**Attribution:** This is an *independent* project applying methods studied in IIT Roorkee × Masai Agentic Systems & Design coursework. It is **not an official IIT Roorkee capstone, Army project, deployment, certification, endorsement or collaboration**. The IIT Roorkee × Masai capstone in the CV is a separate *Agentic Loan Support System*.

## Why this project?

Inspired by public descriptions of cybersecurity training, SOC assessment, and supervised multi-agent workflows in the Indian Army Internship Programme. It showcases defensive AI/data engineering, modular workflow design, transparent detection, evidence retention, instructor approval and reproducible assessment.

## What works

1. **Ingestion agent:** schema-checks, validates event IDs and timestamps, and sorts synthetic CSV logs.
2. **Detection agent:** interpretable repeated login, post-failure success, denied restricted resource, large transfer, endpoint alert and unauthorised privilege-change rules.
3. **Correlation agent:** assembles training cases and links source event IDs.
4. **Guidance agent:** retrieves approved response playbooks with TF-IDF; it makes *no generative or LLM claims*.
5. **Instructor review agent:** logs decisions in an append-only hash-chained audit file; does *not* execute any external action.
6. **Learning evaluation:** synthetic fixture precision/recall/F1, an instructor quiz and a local Streamlit dashboard.

## Instant no-install showcase

Open `dashboard.html` in any modern browser. This is a **read-only, self-contained** case/alert/playbook dashboard populated from the tested Python CLI output. It does not edit real systems. Use Streamlit below for the instructor audit workflow.

## Quick start

Python 3.10+ required.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python generate_sample.py
python run_demo.py
streamlit run app.py
pytest -q
```

Open the Streamlit local link in your browser. `run_demo.py` can be run without Streamlit if pandas and scikit-learn are installed.

## Project layout

- `dashboard.html` — portable browser demo (opens without a Python setup)
- `app.py` — tabs for overview, cases, playbook search, instructor audit and learning assessment
- `sentinel.py` — five deterministic specialised roles, explained below
- `generate_sample.py` — deterministic synthetic fixture generator
- `data/synthetic_soc_events.csv` — simulation event IDs, timestamps, source addresses (reserved/private only), statuses, and training labels
- `data/playbooks.json` — locally maintained playbooks and bibliographic labels (not automatically fetched authoritative texts)
- `run_demo.py` — CLI demonstration and JSON export
- `tests/test_sentinel.py` — unit/integration tests
- `docs/ARCHITECTURE.md` — data flow, limitations, safe extension ideas
- `docs/INTERVIEW_PREP.md` — 60-second pitch and technical Q&A

## Demo script for an interviewer (60 seconds)

1. Show the 6 alert categories and linked event evidence.
2. Open a correlated case and explain why a rule fired.
3. Search the local playbooks for response steps, showing exact grounded provenance.
4. Record a mock instructor decision and demonstrate audit verification.
5. Explain that offline, synthetic-only operation and human approval protect sensitive environments.

## Safety and limitations

- **Only synthetic training data**; no Indian Army logs, data, images, network access or infrastructure are used.
- No system scans, offensive operations, exploitation, real remediation, remote connections, or sensitive data ingestion.
- The rules are pedagogical; they have not been independently benchmarked, certified, deployed, or security-audited.
- The modules are **deterministic agent roles / orchestration**, not LangGraph, MCP or LLM implementation. Those frameworks are in the separate official coursework capstone.
- Synthetic-event precision and recall are **not generalizable production metrics**.
- Hash chaining detects record alteration but **does not prevent** deletion of the entire file or provide cryptographic signatures; real systems need authentication, secure storage and external logging.

## Suggested extension to demonstrate original engineering

Add a false-positive suppression strategy and write two tests for it, then benchmark on a larger *still synthetic* dataset. Document the exact change in your GitHub commit and be ready to explain why you selected the thresholds.
