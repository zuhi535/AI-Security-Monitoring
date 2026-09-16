# AI Security Monitoring — Detection Engine

A **FastAPI backend service** that ingests security event logs (from servers, applications, or any log source), runs them through a **rule‑based threat detection engine**, and persists both the raw log and any resulting alerts in PostgreSQL — the foundation of a SIEM‑style ("Security Information and Event Management") monitoring platform.

> 🌱 **Branch scope (`detection-engine_1.0`):** this branch delivers the **core detection engine** and its ingestion API. It currently implements **rule/pattern‑based** threat detection (regex + keyword matching); no trained machine‑learning model is included yet in this branch — see [Roadmap](#-roadmap--limitations).

---

## 📑 Table of Contents

- [Overview](#overview)
- [Features](#-features)
- [How a Log Is Processed](#-how-a-log-is-processed)
- [Detection Rules](#-detection-rules)
- [Data Model](#-data-model)
- [API Reference](#-api-reference)
- [Project Structure](#-project-structure)
- [Requirements](#-requirements)
- [Getting Started](#-getting-started)
- [Configuration](#-configuration)
- [Testing the Detection Engine](#-testing-the-detection-engine)
- [Roadmap / Limitations](#-roadmap--limitations)

---

## Overview

Client systems (SSH servers, web servers, applications, etc.) submit **security events** to a single REST endpoint (`POST /api/logs`). Every submitted event is:

1. **Persisted** as a `SecurityLog` row.
2. **Analyzed** by the detection engine, which checks the event against a set of rules covering common attack patterns (brute force, SQL injection, XSS, path traversal, suspicious command execution, and targeting of privileged accounts).
3. For every rule that matches, a corresponding **`SecurityAlert`** is created and linked back to the originating log entry — giving you an audit trail from raw event → detected threat.

---

## ✨ Features

- 🔌 **Single ingestion endpoint** (`POST /api/logs`) that accepts structured security events from any source.
- 🛡️ **Multi‑category rule-based detection engine**, evaluated automatically on every ingested log — see the full [rule table](#-detection-rules) below.
- 🗂️ **Relational persistence** — every log and every alert it triggers are stored in **PostgreSQL** via SQLAlchemy, with a foreign‑key relationship (`SecurityAlert.security_log_id → SecurityLog.id`) so alerts always trace back to their source event.
- 🧩 **Typed request/response validation** via Pydantic schemas (`SecurityLogCreate` / `SecurityLogResponse`).
- ❤️ **Health check endpoint** (`GET /health`) for uptime/monitoring integrations.
- 🐳 **One‑command database setup** — PostgreSQL 17 via `docker-compose.yml`.
- ⚙️ **Environment‑based configuration** — database credentials/host/port supplied via `.env` (see `.env.example`), loaded with `python-dotenv`.
- 🧪 **Manual test harness** (`test_detection.py`) exercising all five detection categories with realistic sample events, no database required.

---

## 🔄 How a Log Is Processed

```
        Client / log source
                │
                │  POST /api/logs
                │  { source, source_ip, event_type, username, message, severity }
                ▼
    ┌───────────────────────────┐
    │   app/api/logs.py         │
    │   create_security_log()   │
    └─────────────┬─────────────┘
                  │ 1. persist
                  ▼
    ┌───────────────────────────┐
    │   models/security_log.py  │
    │   SecurityLog row saved    │──► PostgreSQL: security_logs
    └─────────────┬─────────────┘
                  │ 2. analyze
                  ▼
    ┌────────────────────────────────┐
    │ app/services/detection_engine.py│
    │ detect_threats(...)             │
    │  → list[Detection]              │
    └─────────────┬────────────────────┘
                  │ 3. one alert per matched rule
                  ▼
    ┌───────────────────────────┐
    │ models/security_alert.py  │
    │ SecurityAlert row(s) saved │──► PostgreSQL: security_alerts
    └─────────────┬─────────────┘
                  │ 4. response
                  ▼
        SecurityLogResponse (JSON)
```

---

## 🕵️ Detection Rules

Implemented in `app/services/detection_engine.py`. Every submitted log is checked against **all** rules below; a single event can trigger **multiple** alerts (e.g. a failed login attempt against the `admin` account triggers both `FAILED_LOGIN` and `PRIVILEGED_ACCOUNT_TARGET`).

| Rule (`rule_name`) | Severity | Confidence | Trigger condition |
|---|---|---|---|
| **`FAILED_LOGIN`** | HIGH | 0.85 | `event_type` is one of `login_failed`, `authentication_failed`, `failed_login` |
| **`PRIVILEGED_ACCOUNT_TARGET`** | HIGH | 0.90 | `username` matches a privileged account name: `admin`, `administrator`, `root`, `superuser` |
| **`SQL_INJECTION`** | CRITICAL | 0.95 | `message` matches a SQL‑injection pattern (`OR`/`AND` tautologies, `UNION SELECT`, `SELECT … FROM`, `DROP TABLE`, `INSERT INTO`, `DELETE FROM`, trailing SQL comment `--`) |
| **`XSS`** | HIGH | 0.94 | `message` matches a cross‑site‑scripting pattern (`<script`, `javascript:`, `onerror=`, `onload=`, `<iframe`) |
| **`PATH_TRAVERSAL`** | HIGH | 0.93 | `message` matches a path‑traversal pattern (`../`, `..\`, `/etc/passwd`, `/etc/shadow`, `windows\system32`) |
| **`SUSPICIOUS_COMMAND`** | MEDIUM | 0.80 | `message` contains a potentially dangerous command/utility: `wget`, `curl`, `powershell`, `cmd.exe`, `nc`, `netcat`, `chmod`, `base64` |

All pattern matching is **case‑insensitive**. Each `Detection` carries a `rule_name`, `severity`, human‑readable `title`/`description`, and a static `confidence` score, which becomes a `SecurityAlert` row.

---

## 🗄️ Data Model

### `security_logs` (`models/security_log.py`)

| Column | Type | Notes |
|---|---|---|
| `id` | `Integer` (PK) | |
| `timestamp` | `DateTime(timezone=True)` | Defaults to `now(UTC)` |
| `source` | `String(100)` | e.g. `"ssh-server"`, `"web-server"` |
| `source_ip` | `String(45)` | IPv4/IPv6 of the reporting source |
| `event_type` | `String(100)` | e.g. `"login_failed"`, `"http_request"` |
| `username` | `String(100)`, nullable | Account involved, if any |
| `message` | `Text` | Raw event message/payload analyzed by the detection engine |
| `severity` | `String(20)` | Defaults to `"INFO"` |
| `alerts` | relationship → `SecurityAlert` | `cascade="all, delete-orphan"` |

### `security_alerts` (`models/security_alert.py`)

| Column | Type | Notes |
|---|---|---|
| `id` | `Integer` (PK) | |
| `security_log_id` | `Integer` (FK → `security_logs.id`) | Links back to the triggering log |
| `rule_name` | `String(100)` | One of the [detection rules](#-detection-rules) above |
| `severity` | `String(20)` | `MEDIUM` / `HIGH` / `CRITICAL` |
| `title` | `String(255)` | Short human‑readable summary |
| `description` | `Text` | Longer explanation of what was detected |
| `confidence` | `Float` | Static confidence score assigned by the rule |
| `status` | `String(20)` | Defaults to `"OPEN"` (workflow state for triage) |
| `created_at` | `DateTime(timezone=True)` | Defaults to `now(UTC)` |

---

## 🔌 API Reference

### `GET /health`

Simple liveness check.

```json
{
  "status": "healthy",
  "service": "AI Security Monitoring API"
}
```

### `POST /api/logs`

Ingest a new security event. The detection engine runs automatically and any matching alerts are created in the same request.

**Request body** (`SecurityLogCreate`):

```json
{
  "source": "ssh-server",
  "source_ip": "192.168.1.50",
  "event_type": "login_failed",
  "username": "admin",
  "message": "Failed password for admin",
  "severity": "INFO"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `source` | string (1–100 chars) | ✅ | |
| `source_ip` | string (1–45 chars) | ✅ | |
| `event_type` | string (1–100 chars) | ✅ | |
| `username` | string (≤100 chars) | ❌ | |
| `message` | string (min 1 char) | ✅ | |
| `severity` | string (≤20 chars) | ❌ | Defaults to `"INFO"` |

**Response** (`SecurityLogResponse`, `200 OK`): the persisted log record, including its generated `id` and `timestamp`. (Any generated alerts are stored in `security_alerts`; this endpoint currently returns the log itself, not the list of alerts — see [Roadmap](#-roadmap--limitations).)

```json
{
  "id": 1,
  "timestamp": "2026-09-16T12:34:56Z",
  "source": "ssh-server",
  "source_ip": "192.168.1.50",
  "event_type": "login_failed",
  "username": "admin",
  "message": "Failed password for admin",
  "severity": "INFO"
}
```

---

## 📁 Project Structure

```
AI-Security-Monitoring-detection-engine_1.0/
├── docker-compose.yml
├── .env.example
└── backend/
    ├── requirements.txt
    ├── test_detection.py
    ├── app/
    │   ├── main.py
    │   ├── database.py
    │   ├── init_db.py
    │   ├── api/
    │   ├── schemas/
    │   └── services/
    └── models/
```

### `backend/app/`

The FastAPI application itself.

- **`main.py`** — creates the `FastAPI` app, registers the logs router, and exposes `GET /health`.
- **`database.py`** — builds the PostgreSQL connection string from environment variables (`POSTGRES_*`, loaded via `python-dotenv`), URL‑encodes the password, and configures the SQLAlchemy `engine` / `SessionLocal` session factory.
- **`init_db.py`** — one‑off script that creates all tables (`security_logs`, `security_alerts`) via `Base.metadata.create_all(bind=engine)`.

### `backend/app/api/`

- **`logs.py`** — defines the `/api/logs` router: the `POST` handler saves the incoming log, runs `detect_threats()`, persists a `SecurityAlert` for every match, and returns the saved log.

### `backend/app/schemas/`

- **`security_log.py`** — Pydantic models `SecurityLogCreate` (inbound validation) and `SecurityLogResponse` (outbound serialization, `from_attributes` enabled for ORM objects).

### `backend/app/services/`

- **`detection_engine.py`** — the rule engine described in [Detection Rules](#-detection-rules): a pure function `detect_threats(...)` that returns a list of `Detection` dataclass instances, with no side effects or database access of its own (making it easy to unit‑test in isolation — see `test_detection.py`).

### `backend/models/`

SQLAlchemy 2.0‑style declarative ORM models.

- **`base.py`** — shared `Base(DeclarativeBase)` used by all models.
- **`security_log.py`** — the `SecurityLog` table (see [Data Model](#-data-model)).
- **`security_alert.py`** — the `SecurityAlert` table, foreign‑keyed to `SecurityLog` (see [Data Model](#-data-model)).

### Root files

- **`docker-compose.yml`** — spins up **PostgreSQL 17**, configured entirely from environment variables (`POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_PORT`), with a named volume (`postgres_data`) for persistence.
- **`.env.example`** — template for the environment variables the app and `docker-compose.yml` expect (`POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, `POSTGRES_PORT`).
- **`backend/requirements.txt`** — Python dependencies (see below).

---

## 🧰 Requirements

- **Python 3.11+** (uses `str | None` union syntax and SQLAlchemy 2.0 `Mapped[...]` typing)
- **Docker** and **Docker Compose** (for PostgreSQL)
- Key packages from `backend/requirements.txt`:

  | Package | Purpose |
  |---|---|
  | `fastapi` | Web framework / API layer |
  | `uvicorn` | ASGI server |
  | `SQLAlchemy` | ORM / database engine |
  | `psycopg2-binary` | PostgreSQL driver |
  | `pydantic` / `pydantic-settings` | Request/response validation |
  | `python-dotenv` | Loads `.env` configuration |

---

## 🚀 Getting Started

```bash
# 1. Clone the repository and switch to this branch
git clone https://github.com/zuhi535/AI-Security-Monitoring.git
cd AI-Security-Monitoring
git checkout detection-engine_1.0

# 2. Configure environment variables
cp .env.example .env
# then edit .env and set a real POSTGRES_PASSWORD

# 3. Start PostgreSQL
docker compose up -d

# 4. Set up the Python backend
cd backend
python -m venv .venv
source .venv/bin/activate      # on Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 5. Create the database tables
python -m app.init_db

# 6. Start the API server (run from the backend/ directory)
uvicorn app.main:app --reload
```

The API is now available at `http://localhost:8000`, with interactive docs (Swagger UI) at `http://localhost:8000/docs`.

**Try it out:**

```bash
curl -X POST http://localhost:8000/api/logs \
  -H "Content-Type: application/json" \
  -d '{
        "source": "web-server",
        "source_ip": "10.0.0.25",
        "event_type": "http_request",
        "message": "'"'"' OR 1=1 --"
      }'
```

This should be flagged by the `SQL_INJECTION` rule and produce a corresponding `security_alerts` row.

---

## ⚙️ Configuration

All configuration is supplied via environment variables (`.env`, based on `.env.example`) and consumed both by `docker-compose.yml` and `backend/app/database.py`:

| Variable | Example | Description |
|---|---|---|
| `POSTGRES_DB` | `security_monitor` | Database name |
| `POSTGRES_USER` | `security_user` | Database user |
| `POSTGRES_PASSWORD` | `your_secure_password` | Database password (URL‑encoded automatically before building the connection string) |
| `POSTGRES_HOST` | `localhost` | Database host as seen by the backend process |
| `POSTGRES_PORT` | `5432` | Host port mapped to the container's PostgreSQL port |

---

## 🧪 Testing the Detection Engine

`backend/test_detection.py` exercises `detect_threats()` directly, with **no database or running server required**:

```bash
cd backend
python test_detection.py
```

It runs five representative scenarios and prints the resulting detections to the console:

1. Failed login against the `admin` account → `FAILED_LOGIN` + `PRIVILEGED_ACCOUNT_TARGET`
2. Classic SQL injection payload (`' OR 1=1 --`) → `SQL_INJECTION`
3. Reflected XSS payload (`<script>alert(1)</script>`) → `XSS`
4. Path traversal attempt (`GET ../../etc/passwd`) → `PATH_TRAVERSAL`
5. Suspicious command execution (`wget http://example.com/payload.sh`) → `SUSPICIOUS_COMMAND`

---

## 🗺️ Roadmap / Limitations

- **No ML model yet** — despite the project's name, this branch's detection engine is entirely **rule/pattern‑based** (regex + keyword matching with static confidence scores). A learned/statistical anomaly‑detection component is a natural next step for a future branch.
- **No authentication/authorization** on the API yet — `POST /api/logs` and `GET /health` are open endpoints; adding auth (API keys, OAuth2, etc.) is recommended before exposing this beyond a trusted network.
- **No read endpoints yet** — there is currently no `GET` endpoint to list/filter security logs or alerts (e.g. for a dashboard or SIEM front-end); only ingestion (`POST /api/logs`) is implemented.
- **Response shape** — `POST /api/logs` currently returns only the created `SecurityLog`; it does not yet include the list of `SecurityAlert`s generated in the same request.
- **First match per category** — within a single rule category (e.g. SQL injection patterns), detection stops at the first matching pattern (`break`), so only one alert per category is created per log, even if multiple patterns in that category match.
- **No automated test suite** — `test_detection.py` is a manual/print-based script rather than an automated (`pytest`) test suite with assertions.
- **No frontend/dashboard** — this branch is backend/API only.
