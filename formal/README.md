# Provider webhook verification model

`provider_verification.qnt` is a bounded executable model of the pure transition
from untrusted provider input to `VerifiedEvent`.

The model intentionally covers the authentication boundary only. This crate
does not own balances, prices, refunds, credits, invoices, currency conversion,
or ledger arithmetic. Those monetary invariants belong in the billing/ledger
components that parse and apply the authenticated payload.

## Production refinement map

| Model gate | Stripe production path | PayPal production path |
| --- | --- | --- |
| `configuration_valid` | non-empty webhook secret | supported `SHA256withRSA` and non-empty configured webhook id |
| `envelope_valid` | one timestamp plus one or more parseable `v1` signatures | base64/PKCS#1 signature and parseable X.509 RSA certificate |
| `provenance_valid` | timestamp is within the caller-supplied inclusive tolerance | certificate URL is HTTPS, credential-free, and hosted by `paypal.com` or a subdomain |
| `signature_valid` | constant-time HMAC-SHA256 match over `timestamp.raw_body` | RSA-SHA256 match over the exact PayPal signed message |
| `event_valid` | authenticated JSON contains string `id` and `type` | authenticated JSON contains string `id` and `type` or `event_type` |
| `outputs` | one logical successful `stripe::verify` verdict for the modeled input | one logical successful `paypal::verify` verdict for the modeled input |
| `consumes` | caller accepts the verified value once | caller accepts the verified value once |

`tests/formal_verifier_refinement.rs` enumerates all 32 combinations of the five
modeled gates independently for Stripe and PayPal using the public verifier
APIs and real HMAC/RSA operations. A result is accepted if and only if every
gate for that provider is valid. Successful results must preserve the exact
authenticated bytes and expected event identity.

## Verified properties

Within the finite model, for one logical provider input:

- the verifier records at most one accepted verdict;
- no accepted verdict exists unless every modeled authentication gate holds;
- a rejected input cannot be consumed;
- a verified value can be logically consumed at most once by the modeled caller;
- retries after a recorded decision do not change that decision;
- closure cannot manufacture a verified value.

## PayPal freshness boundary

The current PayPal verifier signs and verifies `transmission_time`, but does not
parse it or compare it with an injected clock. Therefore this model does **not**
claim PayPal replay-window freshness. Issue #9 tracks a backward-compatible,
injected-time verifier and the corresponding refinement extension. Downstream
provider-event identity plus authenticated-payload-digest idempotency remains a
separate obligation in `fiducia-customer.rs`.

## Proof boundary

This is bounded verification plus finite refinement testing. It is not an
unbounded proof and does not prove certificate-chain fetching, CA validation,
HTTP behavior, database transactions, scheduler fairness, provider delivery,
downstream idempotency, or the semantic correctness of provider payload fields.
