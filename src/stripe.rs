//! Stripe webhook signature verification.
//!
//! Stripe signs each webhook with the endpoint's signing secret (`whsec_…`) and
//! sends a `Stripe-Signature` header:
//!
//! ```text
//! t=1680000000,v1=5257a869e7…,v1=<second scheme>,v0=<legacy>
//! ```
//!
//! The signed payload is the literal `"{t}.{raw_body}"`, HMAC-SHA256'd with the
//! secret; the hex digest must equal one of the `v1` values. We also bound `t`
//! against the caller-supplied current time so a captured-but-old event cannot
//! be replayed. Reference: https://docs.stripe.com/webhooks/signature
//!
//! `verify` takes `now_unix` explicitly rather than reading the clock, so the
//! logic is deterministic and unit-testable and has no ambient time dependency.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::VerifyError;
use crate::event::VerifiedEvent;
use crate::provider::Provider;

type HmacSha256 = Hmac<Sha256>;

/// Stripe's default replay tolerance is five minutes; expose it as the default
/// but let callers tighten it.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;

/// Verify a Stripe webhook and return the authenticated event.
///
/// * `payload`     — the RAW request body bytes, exactly as received (Stripe
///   signs the bytes; any reserialization breaks the signature).
/// * `sig_header`  — the `Stripe-Signature` header value.
/// * `secret`      — the endpoint signing secret (`whsec_…`).
/// * `now_unix`    — current unix time, for the tolerance check.
/// * `tolerance`   — max allowed |now - t|; use [`DEFAULT_TOLERANCE_SECS`].
pub fn verify(
    payload: &[u8],
    sig_header: &str,
    secret: &str,
    now_unix: i64,
    tolerance_secs: u64,
) -> Result<VerifiedEvent, VerifyError> {
    if secret.is_empty() {
        return Err(VerifyError::InvalidInput("empty signing secret".into()));
    }

    let (timestamp, v1_signatures) = parse_signature_header(sig_header)?;

    // Replay window first: a fresh forgery and a stale replay are both rejected,
    // but ordering the cheap timestamp check before the HMAC avoids doing crypto
    // for an obviously-stale request.
    let skew = now_unix - timestamp;
    if skew.unsigned_abs() > tolerance_secs {
        return Err(VerifyError::TimestampOutOfTolerance {
            skew_secs: skew,
            tolerance_secs,
        });
    }

    // signed_payload = "{t}.{body}"
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| VerifyError::InvalidInput("secret unusable as HMAC key".into()))?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    let expected = mac.finalize().into_bytes();

    // Stripe may send several `v1` values during a secret rotation; accept if ANY
    // matches. Compare in constant time and decode-compare bytes (not hex
    // strings) so length/charset quirks can't leak through string compare.
    let matched = v1_signatures.iter().any(|candidate| {
        hex::decode(candidate)
            .ok()
            .filter(|bytes| bytes.len() == expected.len())
            .is_some_and(|bytes| bytes.ct_eq(expected.as_slice()).into())
    });
    if !matched {
        return Err(VerifyError::SignatureMismatch);
    }

    VerifiedEvent::from_body(Provider::Stripe, payload)
}

/// Pull `t` and every `v1=` value out of a `Stripe-Signature` header. Unknown
/// schemes (`v0`, future `vN`) are ignored; a missing `t` or zero `v1` values is
/// a malformed header.
fn parse_signature_header(header: &str) -> Result<(i64, Vec<String>), VerifyError> {
    if header.trim().is_empty() {
        return Err(VerifyError::MissingSignature);
    }
    let mut timestamp: Option<i64> = None;
    let mut v1 = Vec::new();
    for part in header.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or(VerifyError::MalformedSignature)?;
        match key.trim() {
            "t" => {
                timestamp = Some(
                    value
                        .trim()
                        .parse::<i64>()
                        .map_err(|_| VerifyError::MalformedSignature)?,
                );
            }
            "v1" => v1.push(value.trim().to_string()),
            _ => {} // ignore other schemes
        }
    }
    let timestamp = timestamp.ok_or(VerifyError::MalformedSignature)?;
    if v1.is_empty() {
        return Err(VerifyError::MalformedSignature);
    }
    Ok((timestamp, v1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test_secret_key_value";
    const BODY: &str = r#"{"id":"evt_123","type":"invoice.paid","data":{}}"#;

    /// Produce a valid header the way Stripe would, so tests exercise the real
    /// HMAC rather than a hardcoded digest.
    fn sign(body: &str, secret: &str, t: i64) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(t.to_string().as_bytes());
        mac.update(b".");
        mac.update(body.as_bytes());
        format!("t={t},v1={}", hex::encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn accepts_a_valid_fresh_signature() {
        let t = 1_680_000_000;
        let header = sign(BODY, SECRET, t);
        let event = verify(BODY.as_bytes(), &header, SECRET, t + 10, DEFAULT_TOLERANCE_SECS)
            .expect("valid signature must verify");
        assert_eq!(event.provider, Provider::Stripe);
        assert_eq!(event.id, "evt_123");
        assert_eq!(event.event_type, "invoice.paid");
    }

    #[test]
    fn rejects_a_tampered_body() {
        let t = 1_680_000_000;
        let header = sign(BODY, SECRET, t);
        let tampered = r#"{"id":"evt_123","type":"invoice.paid","data":{"amount":999999}}"#;
        let err = verify(tampered.as_bytes(), &header, SECRET, t, DEFAULT_TOLERANCE_SECS)
            .unwrap_err();
        assert!(matches!(err, VerifyError::SignatureMismatch));
    }

    #[test]
    fn rejects_the_wrong_secret() {
        let t = 1_680_000_000;
        let header = sign(BODY, SECRET, t);
        let err = verify(BODY.as_bytes(), &header, "whsec_attacker", t, DEFAULT_TOLERANCE_SECS)
            .unwrap_err();
        assert!(matches!(err, VerifyError::SignatureMismatch));
    }

    #[test]
    fn rejects_a_stale_replay_outside_tolerance() {
        let t = 1_680_000_000;
        let header = sign(BODY, SECRET, t);
        // now is 10 minutes later, tolerance 5 minutes.
        let err = verify(BODY.as_bytes(), &header, SECRET, t + 600, DEFAULT_TOLERANCE_SECS)
            .unwrap_err();
        assert!(matches!(err, VerifyError::TimestampOutOfTolerance { .. }));
    }

    #[test]
    fn accepts_within_tolerance_on_either_side() {
        let t = 1_680_000_000;
        let header = sign(BODY, SECRET, t);
        // Clock skew in both directions inside the window verifies.
        assert!(verify(BODY.as_bytes(), &header, SECRET, t + 299, DEFAULT_TOLERANCE_SECS).is_ok());
        assert!(verify(BODY.as_bytes(), &header, SECRET, t - 299, DEFAULT_TOLERANCE_SECS).is_ok());
    }

    #[test]
    fn accepts_when_one_of_several_v1_values_matches_rotation() {
        let t = 1_680_000_000;
        let good = sign(BODY, SECRET, t);
        // Prepend a bogus v1 (secret rotation leaves two live signatures).
        let header = format!("t={t},v1=deadbeef,{}", good.split_once(',').unwrap().1);
        assert!(verify(BODY.as_bytes(), &header, SECRET, t, DEFAULT_TOLERANCE_SECS).is_ok());
    }

    #[test]
    fn rejects_missing_and_malformed_headers() {
        assert!(matches!(
            verify(BODY.as_bytes(), "", SECRET, 0, DEFAULT_TOLERANCE_SECS).unwrap_err(),
            VerifyError::MissingSignature
        ));
        assert!(matches!(
            verify(BODY.as_bytes(), "v1=abc", SECRET, 0, DEFAULT_TOLERANCE_SECS).unwrap_err(),
            VerifyError::MalformedSignature
        ));
        assert!(matches!(
            verify(BODY.as_bytes(), "t=notanumber,v1=abc", SECRET, 0, DEFAULT_TOLERANCE_SECS)
                .unwrap_err(),
            VerifyError::MalformedSignature
        ));
    }

    #[test]
    fn rejects_empty_secret() {
        assert!(matches!(
            verify(BODY.as_bytes(), "t=1,v1=abc", "", 1, DEFAULT_TOLERANCE_SECS).unwrap_err(),
            VerifyError::InvalidInput(_)
        ));
    }
}
