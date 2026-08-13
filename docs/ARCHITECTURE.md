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
- **Target adapter:** a small protocol that keeps target behavior independent of
  scoring. Version 0.1 deliberately ships only a deterministic local adapter.
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

## Extension boundary

A future HTTP target adapter must remain disabled by default. It should require
an explicit host allowlist, reject redirects, resolve DNS before each request,
block metadata and link-local ranges, limit response size and time, and record
authorization context. This boundary prevents an evaluation server from becoming
an SSRF proxy.

