# Custom control packs

Control packs let teams add organization-specific checks without loading Python
code or plugins. RAGShield accepts data-only JSON files up to 256 KB and a
maximum of 100 controls.

```bash
ragshield --profile demo-hardened \
  --control-pack examples/control-pack.json \
  --format json
```

Each control requires an identifier, title, category, severity, description,
prompt, expected markers, forbidden markers, mitigation, and OWASP mapping.
Optional fields are `poison_document` and `atlas_technique`. Marker checks are
case-insensitive; a forbidden marker always overrides a safe marker.

Custom payloads should remain inert. Do not add destructive instructions, real
credentials, personal data, or content that targets systems without permission.

