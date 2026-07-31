# Security Policy

`fiducia-payments.rs` handles security-critical payment-webhook verification. Please report suspected vulnerabilities privately so maintainers can investigate and prepare a coordinated fix before details become public.

## Supported code

The current `main` branch is the supported development line. A release branch or older tag is supported only when its release notes explicitly say so. Reports involving an integration should identify both this library and the consuming service, such as `fiducia-customer.rs`, because deployment behavior may span repositories.

## Private reporting

Do **not** open a public issue, discussion, pull request, or social-media thread for an unpatched vulnerability.

Use GitHub's **Security → Report a vulnerability** flow when it is available for this repository. If that private reporting control is unavailable, email `hello@fiducia.cloud` with a subject beginning:

```text
[SECURITY][fiducia-payments.rs]
```

Include only the information needed to reproduce and assess the issue:

- affected commit, tag, API, and payment provider;
- impact and the prerequisites an attacker needs;
- a minimal reproduction or test case;
- redacted logs or stack traces;
- whether the behavior affects confidentiality, integrity, availability, or billing state;
- any suggested mitigation and any disclosure deadline you are working under;
- a safe way to contact you for follow-up.

Never send payment credentials, webhook secrets, private keys, access tokens, customer payloads, or other live sensitive data. Redact identifiers and coordinate a safer transfer method before sharing any evidence that cannot be sanitized.

## High-priority areas

Reports are especially useful when they demonstrate one of these failures:

- Stripe or PayPal signature-verification bypass;
- ambiguous parsing, canonicalization, or constant-time comparison errors;
- timestamp or replay-window bypass;
- certificate URL, certificate parsing, trust, or key-substitution weaknesses;
- a path from unverified input to `VerifiedEvent`;
- provider-event identity or idempotency failures that can duplicate billing mutations;
- secret, raw payload, or sensitive metadata disclosure;
- panic, resource-exhaustion, or dependency behavior reachable through a realistic webhook request;
- a flaw showing that a documented dependency-advisory exception is unsafe for the production verification-only use case.

## Safe testing

Use local tests, fixtures, and payment-provider sandbox accounts that you own or are explicitly authorized to use. Do not probe Fiducia production systems, third-party accounts, or infrastructure; do not perform denial-of-service testing; and do not access, modify, retain, or destroy data that is not yours. Stop testing and report privately if you encounter real customer or credential material.

This policy does not authorize unlawful activity or activity that violates a provider's terms. Good-faith research that follows these boundaries will be evaluated on the technical issue rather than on whether advance notice was possible.

## Handling and disclosure

Maintainers will validate the affected boundary, determine whether downstream services also require changes, prepare tests and fixes, and coordinate an advisory or release when warranted. Please keep the report private until the maintainers and reporter agree that users have had a reasonable opportunity to update.

No bug bounty, payment, response-time guarantee, or severity outcome is promised by this policy.
