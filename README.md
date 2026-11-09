# ScamShield

ScamShield is a portfolio project for checking suspicious emails, messages, and job listings. It focuses on explainability: every result shows the warning signs found, the matching evidence, and the points that produced the final score.

[Try the public demo](https://scamshield-check.kaleabdereje00.chatgpt.site) · [API documentation](http://127.0.0.1:8000/docs)

![ScamShield showing an explained high-risk result](docs/scamshield-demo.png)

## Why I built it

A risk percentage is not useful if the user cannot tell why it appeared. ScamShield treats the score as a summary, not the answer. The interface keeps the evidence, individual weights, sender-domain checks, and link checks visible so the user can make their own decision.

## Features

- Paste an email, text message, or job listing
- See a transparent 0–100 risk score
- Review the exact evidence and points behind every warning
- Inspect links and pasted sender domains
- Save recent scans in SQLite
- Use the responsive browser interface or JSON API

## Technology choices

| Technology | Why it is used |
| --- | --- |
| FastAPI | Small, typed API with automatic OpenAPI documentation |
| SQLite | Simple durable history with no external service required |
| Vanilla HTML/CSS/JS | Keeps the interface lightweight and easy to inspect |
| Pytest | Covers scoring behavior, false positives, link-only input, and database migration |

## Run locally

Requires Python 3.11 or newer.

```bash
git clone https://github.com/kade258/scamshield-python.git
cd scamshield-python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). On Windows PowerShell, activate the environment with `.venv\Scripts\Activate.ps1`.

## Run the tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite covers high-risk scams, ordinary messages, sender-domain handling, false positives, link-only warnings, evidence excerpts, saved history, and migration from an older database schema.

## How scoring works

The analyzer uses explicit weighted rules rather than an AI model. Signals include urgency, threats, sensitive-information requests, unusual payment methods, secrecy, suspicious sender domains, and misleading link patterns.

| Score | Result |
| --- | --- |
| 70–100 | High risk |
| 35–69 | Suspicious |
| 0–34 | Low risk, unless a suspicious domain is present |

A suspicious link or sender domain never receives a “Low risk” label, even when it is the only evidence. In that case the result says **“Limited evidence — suspicious domain detected.”** Scores are capped at 100.

## API

`POST /api/scans` analyzes and saves a message:

```json
{
  "content": "URGENT: verify your account at https://example.com"
}
```

`GET /api/scans` returns recent scans. `GET /health` provides a health check. FastAPI serves interactive API documentation at `/docs` while the app is running.

## Limitations

- ScamShield does not visit links or query live reputation databases.
- A link marked “clear” only means its formatting did not match a built-in warning pattern.
- A pasted sender address cannot authenticate who sent the message.
- The rule weights are product heuristics, not calibrated fraud probabilities.
- Attackers change tactics, so a low score must not be treated as proof of safety.
- Scan history is stored locally in `scamshield.db`; there are no user accounts or cloud sync.

For an unexpected request, verify it using contact information from the organization’s official website or app.

## Project structure

```text
app/
├── analyzer.py        # scoring rules and evidence extraction
├── database.py        # SQLite history and migration
├── main.py            # FastAPI routes
├── static/            # browser JavaScript and styles
└── templates/         # application HTML
tests/                 # analyzer and persistence tests
```

The hosted demo is a separately deployed interface using the same product behavior. This repository contains the Python/FastAPI implementation.
