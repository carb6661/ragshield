<div align="center">

# RAGShield

**Defensive security evaluation for retrieval-augmented generation applications**

[![CI](https://github.com/carb6661/ragshield/actions/workflows/ci.yml/badge.svg)](https://github.com/carb6661/ragshield/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![Vue](https://img.shields.io/badge/Vue-3-42b883)
![License](https://img.shields.io/badge/license-MIT-63f5b1)

</div>

RAGShield is an open-source lab for testing security controls around RAG systems.
It turns prompt injection, poisoned retrieval context, cross-tenant access, data
leakage, and provenance requirements into repeatable controls with evidence and
severity-weighted scoring.

The default release is intentionally safe: it evaluates deterministic local
vulnerable and hardened profiles, makes no network calls, needs no model API key,
and contains no real credentials.

## What it demonstrates

- six defensive controls covering five RAG attack-surface categories;
- vulnerable-versus-hardened baseline comparison;
- OWASP LLM and MITRE ATLAS mappings;
- evidence, remediation, weighted scoring, and Markdown reports;
- persistent scan history and dashboard aggregates;
- production-style FastAPI, Vue 3, SQLite, Docker Compose, tests, and CI.

## Quick start with Docker

```bash
docker compose up --build
```

Open `http://localhost:8080`. API documentation is available at
`http://localhost:8000/docs`.

## Local development

Backend:

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Frontend, in another terminal:

```bash
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173`.

## API example

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_name":"Local lab","target_profile":"demo-vulnerable"}'
```

Profiles are `demo-vulnerable` and `demo-hardened`. Reports can be downloaded
from `GET /api/v1/scans/{scan_id}/report`.

## Control catalog

| ID | Category | Scenario | Severity |
|---|---|---|---|
| PI-001 | Prompt Injection | hidden policy extraction | High |
| RAG-001 | RAG Poisoning | malicious retrieved instruction | Critical |
| ACL-001 | Access Control | cross-tenant document request | Critical |
| PII-001 | Data Leakage | personal data disclosure | High |
| SEC-001 | Data Leakage | credential exfiltration | Critical |
| SRC-001 | Integrity | answer without provenance | Medium |

See [the architecture](docs/ARCHITECTURE.md) and
[threat model](docs/THREAT_MODEL.md) for design details and limitations.

## Verification

```bash
cd backend
ruff check app tests
pytest --cov=app

cd ../frontend
npm run build
```

## Responsible use

Use RAGShield only on applications you own or are explicitly authorized to test.
Version 0.1 does not include an arbitrary HTTP scanner. If you build a network
adapter, keep it opt-in and implement strict allowlisting, DNS and redirect checks,
rate limits, response-size limits, audit logs, and authorization records.

## Contributing and security

Contributions are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security issues privately as described in [SECURITY.md](SECURITY.md).

Released under the [MIT License](LICENSE).

