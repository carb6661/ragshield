# Threat model

## Assets

- trusted system instructions and model configuration;
- tenant-scoped documents and retrieval metadata;
- credentials, personal data, and confidential indexed content;
- answer provenance and the integrity of the knowledge base;
- evaluation evidence and scan history.

## Trust boundaries

User prompts and retrieved documents are untrusted. Generated text is also
untrusted until output controls have run. Tenant identity must be applied before
retrieval and verified again before returned chunks enter model context.

## Covered threats

| Threat | Security property | Control |
|---|---|---|
| Direct prompt injection | instruction integrity | PI-001 |
| Malicious retrieved instructions | context integrity | RAG-001 |
| Cross-tenant retrieval | authorization | ACL-001 |
| Personal data disclosure | confidentiality | PII-001 |
| Secret exfiltration | confidentiality | SEC-001 |
| Unsupported answers | provenance | SRC-001 |

The mappings are informed by OWASP guidance for LLM applications and the MITRE
ATLAS knowledge base. A passing result is evidence for the exact deterministic
scenario only; it does not prove a target is secure against adaptive attackers.

## Out of scope

- model training and weight attacks;
- availability or high-volume load testing;
- automated scanning of arbitrary internet hosts; HTTP evaluation is limited to
  exact hosts configured by the server operator;
- malware generation, exploitation, or persistence;
- certification against a legal or regulatory standard.
