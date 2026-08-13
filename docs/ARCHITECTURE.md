# Architecture

RAGShield separates evaluation policy from target execution so that controls can
be tested deterministically without an external model or network connection.

```text
Vue security console
        |
        | JSON / report download
        v
FastAPI API  -->  SQLite scan history
        |
        v
Evaluation engine
   | rules + mappings
   | target adapter
   | marker evaluation
   v
Local vulnerable / hardened RAG profiles
```

## Components

- **Control library:** immutable rule definitions with payload, expected safety
  behavior, forbidden leakage markers, mitigation, severity, and mappings.
- **Target adapters:** a small protocol keeps execution independent of scoring.
  Deterministic demo profiles are always available; the HTTP adapter is an
  operator-enabled integration for exact allowlisted hosts.
- **Scanner:** evaluates controls, gives forbidden evidence priority over generic
  refusal text, and computes a severity-weighted posture score.
- **API:** exposes control metadata, scan execution, history, dashboard aggregates,
  and Markdown report export.
- **Console:** presents posture, attack-surface distribution, evidence, control
  mappings, and baseline comparisons.

## Scoring

Critical, high, medium, and low controls carry weights of 25, 16, 9, and 4.
The score is the percentage of total control weight that held. This is a project
metric for comparing controlled test runs, not a compliance certification.

## Network boundary

The HTTP target adapter remains disabled by default. It requires an explicit
hostname allowlist, rejects redirects, resolves DNS, blocks non-global ranges by
default, ignores environment proxy settings, and limits response size and time.
This boundary prevents an evaluation server from becoming an SSRF proxy. Private
and insecure HTTP targets require separate operator flags intended only for an
isolated local lab.
