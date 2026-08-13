<div align="center">

# RAGShield

**Defensive security evaluation for retrieval-augmented generation applications**

[![CI](https://github.com/carb6661/ragshield/actions/workflows/ci.yml/badge.svg)](https://github.com/carb6661/ragshield/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![Vue](https://img.shields.io/badge/Vue-3-42b883)
![License](https://img.shields.io/badge/license-MIT-63f5b1)
![Coverage](https://img.shields.io/badge/coverage-94%25-63f5b1)

</div>

English · [简体中文](README.zh-CN.md)

RAGShield is an open-source toolkit for testing security controls around RAG systems.
It turns prompt injection, poisoned retrieval context, cross-tenant access, data
leakage, and provenance requirements into repeatable controls with evidence and
severity-weighted scoring.

The default mode is intentionally safe: it evaluates deterministic local
vulnerable and hardened profiles, makes no network calls, needs no model API key,
and contains no real credentials.

It can also evaluate an owned JSON endpoint, but only after the server operator
enables an exact hostname allowlist. This makes RAGShield useful in staging and CI
without turning a shared deployment into an arbitrary network scanner.

## What it demonstrates

- six built-in controls covering five RAG attack-surface categories;
- vulnerable-versus-hardened baseline comparison;
- OWASP LLM and MITRE ATLAS mappings;
- authorized HTTP target adapter with SSRF-resistant defaults;
- Markdown, JSON, and SARIF reports for humans and GitHub Code Scanning;
- strict data-only custom control packs;
- standalone CLI with severity-based CI exit codes;
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

Install the CLI from a checkout:

```bash
cd backend
pip install .
ragshield --profile demo-vulnerable --format sarif --output ragshield.sarif
```

The CLI exits with status `1` when a finding meets `--fail-on` (default: high),
status `2` for configuration errors, and `0` when the policy passes. Use
`--fail-on never` for observation-only runs.

## API example

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_name":"Local lab","target_profile":"demo-vulnerable"}'
```

Profiles are `demo-vulnerable` and `demo-hardened`. Reports can be downloaded
from `GET /api/v1/scans/{scan_id}/report`.

Use `?format=markdown`, `?format=json`, or `?format=sarif` to select a report.

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
[threat model](docs/THREAT_MODEL.md) for design details and limitations. To test
an owned staging system, follow the [authorized HTTP integration guide](docs/HTTP_INTEGRATION.md).
To add organization-specific checks, see [custom control packs](docs/CONTROL_PACKS.md).

## CI example

```yaml
- name: Run RAGShield baseline
  working-directory: backend
  run: |
    pip install .
    ragshield --profile demo-hardened --format sarif --output ragshield.sarif

- name: Upload security results
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: backend/ragshield.sarif
```

For a staging endpoint, configure `RAGSHIELD_ENABLE_NETWORK_TARGETS` and the exact
`RAGSHIELD_HTTP_TARGET_ALLOWLIST` in protected CI variables. Do not put bearer
tokens into a repository or a control pack.

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
RAGShield does not include an arbitrary internet scanner. Version 0.2 provides
an opt-in adapter with exact allowlisting, DNS/IP
checks, redirects disabled, environment proxies disabled, and time/size limits.
Only enable it for explicitly authorized targets.

## Roadmap

- signed and versioned community control packs;
- pluggable semantic evaluators alongside deterministic markers;
- scheduled regression comparisons and score trends;
- additional RAG framework adapters and authentication strategies;
- bilingual console and reports.

## Contributing and security

Contributions are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md). Please report
security issues privately as described in [SECURITY.md](SECURITY.md).

Released under the [MIT License](LICENSE).
