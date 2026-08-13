# Authorized HTTP target integration

RAGShield 0.2 can evaluate an owned RAG JSON endpoint. Network targets are
disabled by default and require server-operator configuration. A browser user
cannot turn this capability on or choose an arbitrary host.

## Endpoint contract

For every control, RAGShield sends a `POST` request:

```json
{
  "message": "the control prompt",
  "security_context": {
    "control_id": "PI-001",
    "tenant": "alpha",
    "injected_document": null
  }
}
```

The endpoint should return JSON. By default, RAGShield reads the `answer` field;
nested paths such as `data.answer` are supported.

```json
{"answer": "The RAG application's final answer"}
```

The `security_context` values are inert test metadata. A test adapter can use
`injected_document` to add the supplied poisoned document to an isolated test
index. Never point a test adapter at a production write path.

## Enable a host

```bash
RAGSHIELD_ENABLE_NETWORK_TARGETS=true
RAGSHIELD_HTTP_TARGET_ALLOWLIST=rag-staging.example.com
```

Only exact hostnames are accepted. Wildcards, URL credentials, fragments, and
redirects are rejected. Plain HTTP and non-public IP ranges are blocked unless
the operator explicitly enables them for an isolated local lab:

```bash
RAGSHIELD_ALLOW_PRIVATE_TARGETS=true
RAGSHIELD_ALLOW_INSECURE_HTTP=true
```

These two settings should not be enabled on an internet-facing RAGShield server.

## CLI

```bash
export RAGSHIELD_ENABLE_NETWORK_TARGETS=true
export RAGSHIELD_HTTP_TARGET_ALLOWLIST=rag-staging.example.com

ragshield \
  --profile authorized-http \
  --endpoint https://rag-staging.example.com/security-test \
  --response-field data.answer \
  --format sarif \
  --output ragshield.sarif
```

Use `--bearer-token` only with short-lived test credentials. The API and database
never persist the token, but command-line arguments may be visible to local
process inspection. A dedicated test environment and ephemeral credential are
recommended.

## SSRF controls

The adapter uses an exact operator allowlist, resolves DNS before connecting,
rejects non-global addresses by default, disables environment proxies and
redirects, applies time and response-size limits, and never accepts arbitrary
request headers. Deploy it behind authentication if network targets are enabled.

