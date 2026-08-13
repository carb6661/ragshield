# Security policy

## Supported versions

Security fixes are applied to the latest release on the `main` branch.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting feature. Include the affected version, impact,
minimal reproduction, and any suggested remediation. You should receive an
acknowledgement within five working days.

## Safe operation

RAGShield is a defensive evaluation tool. The default release only runs against
deterministic local demonstration targets and does not make network requests.
Do not modify or extend it to evaluate a system unless you own that system or
have explicit written authorization.

Never load production credentials or personal information into the demonstration
target. The credentials shown by the vulnerable profile are inert test strings.

