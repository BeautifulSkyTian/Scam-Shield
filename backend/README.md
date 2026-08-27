# Scam Shield — Backend

FastAPI service that analyzes messages for scam risk.

## Run it

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env          # add your GEMINI_API_KEY
.venv/bin/uvicorn app.main:app --reload --port 8000
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | liveness + remaining free-tier quota |
| `POST` | `/api/analyze` | analyze one message |
| `POST` | `/api/analyze/batch` | analyze up to 50 (use this for an inbox) |
| `GET` | `/api/history` | last 50 stored analyses |

```bash
curl -s localhost:8000/api/analyze -H 'Content-Type: application/json' -d '{
  "message": "Confirm your password within 24 hours or your account closes.",
  "sender": "security@chase-alerts.tk",
  "links": [{"href": "http://chase-verify.tk/login", "text": "chase.com"}]
}'
```

### Request

`message` is the only required field. Everything else is optional:

| Field | Notes |
|---|---|
| `message` | the text to analyze |
| `sender` | email / phone / handle, if the page shows one |
| `links` | **preferred** — `[{href, text}]` for every anchor |
| `url` | legacy single-URL field; still works, merged into `links` |
| `platform`, `page_url`, `message_id` | context, stored with the analysis |

**Send `links`, not `url`.** `text` is what the user sees and `href` is where it goes; when
those disagree it is the strongest scam signal available, and only the content script can
see it.

### Response

The original fields (`risk_score`, `risk_level`, `category`, `summary`, `reasons`,
`recommended_action`) are unchanged. Added, all optional:

| Field | Use |
|---|---|
| `action` | `allow` / `notice` / `warn` / `strong_warn` / `block` — maps 1:1 to the five UI states |
| `headline` | one line for the warning badge |
| `likely_goal` | what the sender is after |
| `confidence` | `low` / `medium` / `high` |
| `links[]` | per-URL verdict and why |
| `tone` | pressure / fear / greed / authority, 0-100 |
| `analyzed_by` | `model`, `prefilter` (no API call), or `link_check_only` (AI failed) |
| `degraded` | true when the AI call failed and this is link checks only |
| `analysis_ms`, `cached` | timing / cache hit |

`reasons[]` also gained `evidence` (a verbatim quote from the message), `severity`,
`contribution` (points added to the score), and `source` (`model` / `link_check`).
Rendering `evidence` next to each reason is what makes the analysis believable.

## The analysis layer

Everything intelligent lives in [`app/analyzer/`](app/analyzer/README.md) — read that for
the design, the scoring model, the free-tier constraints, and measured eval results.
`app/services/ai_service.py` is a thin adapter between it and this API.

## Testing

```bash
.venv/bin/python -m pytest tests/ -q       # 89 offline tests, no key needed
.venv/bin/python -m tools.check_links      # link checker, offline
.venv/bin/python -m tools.demo "message"   # analyze one message from the CLI
.venv/bin/python -m evals.run_eval         # full scorecard against 20 golden cases
```

Full guide: [`app/analyzer/TESTING.md`](app/analyzer/TESTING.md).
