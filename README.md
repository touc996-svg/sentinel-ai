# SENTINEL AI

**Defensive cybersecurity event ingestion and threat detection platform.**

SENTINEL AI collects, validates, stores, and analyzes structured security events. It is a portfolio project and a foundation for explainable detections and analyst-focused incident investigation.

## Current capabilities

- FastAPI event ingestion and retrieval.
- Pydantic payload validation.
- SQLAlchemy persistence with SQLite and PostgreSQL support.
- Event listing and filtering.
- Automated pytest coverage.
- Docker Compose and GitHub Actions CI configuration.

## Architecture

```text
Security Event Sources
        |
        v
FastAPI Ingestion API
        |
        v
Pydantic Validation
        |
        v
Event Service
        |
        v
SQLAlchemy
        |
        v
SQLite / PostgreSQL
```

## Stack

Python, FastAPI, Pydantic, SQLAlchemy, SQLite, PostgreSQL, Docker, pytest, GitHub Actions.

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
uvicorn app.main:app --reload
```

Interactive API docs: http://127.0.0.1:8000/docs

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Application information |
| GET | `/health` | Database health |
| POST | `/api/v1/events` | Ingest event |
| GET  `/api/v1/events` | List and filter events |
| GET  | `/api/v1/events/{event_id}` | Retrieve event |

Example event:

```json
{
  "event_type": "authentication",
  "source": "linux-server",
  "source_ip": "192.168.1.50",
  "username": "admin",
  "outcome": "failure",
  "details": {"method": "ssh", "attempt": 1}
}
```

## Docker

```bash
docker compose up --build -d
docker compose ps
```

API: http://localhost:8000
Docs: http://localhost:8000/docs

Stop containers with `docker compose down`. The named PostgreSQL volume preserves data. `docker compose down -v` also deletes that local database volume.

The default database password is for local development only. Set a strong `POSTGRES_PASSWORD` for any shared or deployed environment. Never commit production credentials.

## Tests

```bash
python -m pytest -q
```

## Security scope

SENTINEL AI is for defensive monitoring, event analysis, incident investigation, and risk prioritization. Future detections and AI recommendations should be explainable and grounded in event evidence.

See [`docs/roadmap.md`](docs/roadmap.md) for planned work.
