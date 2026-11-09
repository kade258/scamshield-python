# ScamShield

ScamShield checks suspicious emails, text messages, and job listings. Each result includes the warning signs it found, the matching text, and the points that contributed to the final risk score.

## Features

- Paste and analyze suspicious messages
- Transparent 0–100 risk score
- Evidence-backed warning signs and point breakdowns
- Sender-domain and link-pattern checks
- Automatic message-type detection
- Local SQLite scan history
- Responsive browser interface
- FastAPI documentation at `/docs`

## Tech stack

- Python 3.11+
- FastAPI
- SQLite
- Vanilla HTML, CSS, and JavaScript
- Pytest

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000).

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Run tests

```bash
pip install -r requirements-dev.txt
pytest
```

## API

### Analyze and save a message

`POST /api/scans`

```json
{
  "content": "URGENT: verify your account at https://example.com"
}
```

### View recent scans

`GET /api/scans`

### Health check

`GET /health`

## How scoring works

The analyzer assigns points for signals such as urgency, threats, requests for sensitive information, unusual payment methods, suspicious sender domains, and misleading links. The total is capped at 100. The score shows risk signals; it does not prove that a message is fraudulent.

## Privacy

Scans are stored in a local `scamshield.db` SQLite file. That file is excluded from Git, so scan contents are never committed to the repository.

## Important limitation

ScamShield does not visit links or query external reputation services. A link marked “clear” only means its formatting did not match the built-in warning patterns. Sender-domain checks are also heuristic: a pasted address cannot authenticate who sent a message. Always verify unexpected requests through an independently trusted channel.
