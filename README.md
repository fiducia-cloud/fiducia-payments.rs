# fiducia-payments

Provider-agnostic payment logic for fiducia.cloud: **webhook signature
verification** and event parsing for **Stripe** and **PayPal**.

This is a pure library. It owns no HTTP server and no database — the customer
backend (`fiducia-customer.rs`) mounts the routes and writes the billing tables
declared in `fiducia-interfaces/sql/customer.sql`. Keeping the security-critical
crypto here, with time and I/O injected by the caller, lets it be exhaustively
unit-tested with no network, no clock, and no Postgres.

## Why signature verification is the load-bearing part

A payments webhook endpoint is an unauthenticated, internet-facing POST that
mutates billing state. If the signature is not verified, anyone can forge
"invoice paid" / "subscription active" events. Both providers sign their
webhooks; this crate does nothing else until that signature checks out, and the
only way to obtain a `VerifiedEvent` is through a verifier — so "did we check
the signature?" is not something a caller can forget.

## Stripe (`stripe::verify`)

Fully offline. Recomputes `HMAC-SHA256(secret, "{t}.{body}")` and constant-time
compares it against the `v1` values in `Stripe-Signature`, and rejects a
timestamp outside the replay-tolerance window. `now_unix` is passed in.

```rust
let event = fiducia_payments::stripe::verify(
    raw_body, sig_header, whsec, now_unix,
    fiducia_payments::stripe::DEFAULT_TOLERANCE_SECS, // 300
)?;
```

## PayPal (`paypal::verify`)

Offline RSA-SHA256 over PayPal's CRC32-bound message
`{transmission_id}|{transmission_time}|{webhook_id}|{crc32(body)}`, verified
against the public key in the certificate at `paypal-cert-url`. The crate:

- builds the signed message (`paypal::signed_message`, pure),
- rejects a `cert-url` that is not a `*.paypal.com` HTTPS host (defense in depth
  — otherwise an attacker's own validly-signed cert would pass),
- verifies the RSA signature against the supplied certificate.

**Fetching the certificate is the caller's responsibility** (it should cache and
pin it). This crate deliberately does not make network calls. Certificate
*chain* validation to PayPal's CA is likewise the caller's concern; the host
gate + RSA verification are what this crate guarantees.

The current PayPal verifier cryptographically binds `transmission_time`, but it
does not parse that timestamp or enforce a replay-tolerance window. Therefore a
successful PayPal `VerifiedEvent` proves authentication of the exact bytes, not
age freshness. Issue #9 tracks a backward-compatible injected-time verifier and
strict timestamp handling. Do not replace downstream idempotency with that
future freshness check; both controls are required at different boundaries.

The `rsa` crate currently carries
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html),
which has no patched release and concerns timing leakage of private keys.
Production code constructs only `RsaPublicKey` and performs verification; the
only private-key operation signs test fixtures offline with an embedded,
non-secret key. CI therefore ignores exactly that advisory ID while continuing
to fail on every other advisory. Adding private-key or decryption behavior
requires replacing the dependency and removing the exception first.

## Idempotent processing

`VerifiedEvent.id` maps to `billing_webhook_events.provider_event_id`. The
customer backend durably keys an accepted event by provider plus provider event
identity and records the SHA-256 digest of `VerifiedEvent.payload`.

An identical authenticated redelivery is a no-op. Reuse of the same provider
event identity with a different authenticated payload digest or event type is a
conflict and must not cause a billing effect. Hash and parse only the exact
verified payload bytes, never a separately re-read or reserialized request
body.

## Formal verification

`formal/provider_verification.qnt` models the provider-authentication lifecycle
from untrusted receipt through verified/rejected verdicts and one logical
consumer acceptance. The pinned CI gate typechecks deterministic traces,
explores 10,000 bounded schedules, checks the model invariant with Apalache on
main/scheduled runs, and refines all 32 combinations of five authentication
gates for both Stripe and PayPal against the real Rust/HMAC/RSA implementation.

This crate contains no balance, price, refund, credit, invoice-total, currency
conversion, or ledger arithmetic. Exact money conservation belongs in the
billing and ledger components that apply authenticated provider events; the
Quaestor executor maintains the dedicated money refinement.

## Testing

`cargo test` — no network. PayPal tests use an embedded self-signed RSA cert +
key fixture (`tests/fixtures/`) so the real cert-parsing + RSA path runs offline.
