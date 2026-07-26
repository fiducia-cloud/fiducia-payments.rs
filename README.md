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
mutates billing state. If the signature isn't verified, anyone can forge
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

The `rsa` crate currently carries
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html),
which has no patched release and concerns timing leakage of private keys.
Production code constructs only `RsaPublicKey` and performs verification; the
only private-key operation signs test fixtures offline with an embedded,
non-secret key. CI therefore ignores exactly that advisory ID while continuing
to fail on every other advisory. Adding private-key or decryption behavior
requires replacing the dependency and removing the exception first.

## Idempotent processing

`VerifiedEvent.id` maps to `billing_webhook_events.provider_event_id`, whose
unique `(provider, provider_event_id)` index makes processing idempotent under a
provider's at-least-once redelivery: `INSERT … ON CONFLICT DO NOTHING`, then
process only the row you actually inserted. Store `signature_verified = true`
and `payload_sha256` of the verified bytes as the audit of the trust decision.

## Testing

`cargo test` — no network. PayPal tests use an embedded self-signed RSA cert +
key fixture (`tests/fixtures/`) so the real cert-parsing + RSA path runs offline.
