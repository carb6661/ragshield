<div align="center">

# RAGShield

**Open-source defensive security evaluation for RAG applications**

[![CI](https://github.com/carb6661/ragshield/actions/workflows/ci.yml/badge.svg)](https://github.com/carb6661/ragshield/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![Vue](https://img.shields.io/badge/Vue-3-42b883)
![Coverage](https://img.shields.io/badge/coverage-94%25-63f5b1)
![License](https://img.shields.io/badge/license-MIT-63f5b1)

English · [简体中文](README.md)

</div>

RAGShield turns prompt injection, poisoned retrieval context, cross-tenant
access, sensitive-data leakage, and provenance requirements into repeatable
security controls with evidence, remediation, and severity-weighted scoring.

The safe default mode is local and deterministic: no model API key, external
network request, or third-party plugin code is required. An operator can enable
an exact hostname allowlist to evaluate an explicitly authorized staging target.

## Highlights

- six built-in controls across five RAG attack-surface categories;
- vulnerable-versus-hardened baseline comparison;
- OWASP LLM and MITRE ATLAS mappings;
- opt-in HTTP adapter with allowlisting and SSRF-resistant defaults;
- Markdown, JSON, and SARIF output;
- CLI severity gates for CI and GitHub Code Scanning;
- strict data-only custom control packs;
- FastAPI, Vue 3, SQLite, Docker Compose, tests, and CI.

## Quick start

```bash
docker compose up --build
```

Open `http://127.0.0.1:8080`; API documentation is available at
`http://127.0.0.1:8000/docs`. Published ports bind to loopback by default.

## CLI

```bash
cd backend
pip install .
ragshield --profile demo-vulnerable --format sarif --output ragshield.sarif
```

List the built-in controls without contacting a target:

```bash
ragshield --list-controls
```

Run a 30-second, network-free comparison with the built-in labs:

```bash
ragshield --profile demo-vulnerable --format markdown --fail-on never
ragshield --profile demo-hardened --format markdown --fail-on never
```

Exit status is `1` when a finding meets `--fail-on` (high by default), `2` for
configuration errors, and `0` when the policy passes. Use `--fail-on never` for
observation-only runs.

## Authorized HTTP integration

Network targets are disabled by default and require operator configuration:

```bash
RAGSHIELD_ENABLE_NETWORK_TARGETS=true
RAGSHIELD_HTTP_TARGET_ALLOWLIST=rag-staging.example.com
```

The adapter uses an exact allowlist, DNS/IP checks, disabled redirects and
environment proxies, plus timeout and response-size limits. Read the
[HTTP integration guide](docs/HTTP_INTEGRATION.md) before enabling it.

## Custom controls

```bash
ragshield --profile demo-hardened \
  --control-pack examples/control-pack.json \
  --format json
```

Control packs are bounded, data-only JSON and never execute plugin code. See
[CONTROL_PACKS.md](docs/CONTROL_PACKS.md).

## Verification

```bash
cd backend
ruff check app tests ../examples
pytest --cov=app

cd ../frontend
npm audit
npm run build
```

## Responsible use and contribution

Only evaluate systems you own or are explicitly authorized to test. RAGShield
is not an arbitrary internet scanner and a passing result is not a certification.

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), the
[architecture](docs/ARCHITECTURE.md), and the [threat model](docs/THREAT_MODEL.md).

Released under the [MIT License](LICENSE).

