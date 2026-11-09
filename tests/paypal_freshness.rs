//! Full signed PayPal webhook -> X.509/RSA -> authenticated event refinement,
//! including RFC3339 replay-window time boundaries and all six failure gates.
//! No network, private customer keys, or real payment events are involved.

use base64::Engine;
use fiducia_payments::{paypal, Provider, VerifyError};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::Sha256;

const CERT: &str = include_str!("fixtures/paypal_test_cert.pem");
const KEY: &str = include_str!("fixtures/paypal_test_key.pem");
const BODY: &[u8] = br#"{"id":"WH-fresh","event_type":"PAYMENT.CAPTURE.COMPLETED"}"#;
const INVALID_EVENT: &[u8] = br#"{"id":"WH-fresh"}"#;
const WEBHOOK: &str = "WH-FRESH";
const CERT_URL: &str = "https://api.paypal.com/v1/notifications/certs/fresh.pem";

fn sign(body: &[u8], timestamp: &str, webhook: &str) -> String {
    let key = RsaPrivateKey::from_pkcs8_pem(KEY).expect("embedded non-secret fixture key");
    let signer = SigningKey::<Sha256>::new(key);
    let msg = paypal::signed_message("transmission-fresh", timestamp, webhook, body);
    base64::engine::general_purpose::STANDARD.encode(signer.sign(msg.as_bytes()).to_bytes())
}

fn transmission<'a>(timestamp: &'a str, signature: &'a str, cert_url: &'a str)
    -> paypal::Transmission<'a>
{
    paypal::Transmission {
        transmission_id: "transmission-fresh",
        transmission_time: timestamp,
        signature_b64: signature,
        cert_url,
        auth_algo: "SHA256withRSA",
    }
}

fn check(timestamp: &str, now: i64, tolerance: u64) -> Result<(), VerifyError> {
    let signature = sign(BODY, timestamp, WEBHOOK);
    paypal::verify_at(
        &transmission(timestamp, &signature, CERT_URL),
        WEBHOOK, BODY, CERT, now, tolerance,
    ).map(|event| {
        assert_eq!(event.provider, Provider::Paypal);
        assert_eq!(event.id, "WH-fresh");
        assert_eq!(event.payload.as_slice(), BODY);
    })
}

#[test]
fn signed_rfc3339_epoch_and_numeric_offset_are_equivalent() {
    for timestamp in [
        "1970-01-01T00:00:00Z",
        "1970-01-01T01:30:00+01:30",
        "1969-12-31T22:30:00-01:30",
        "1970-01-01T00:00:00.000000000Z",
    ] {
        check(timestamp, 0, 0).expect("same instant signs and verifies");
    }
}

#[test]
fn inclusive_replay_window_is_precise_to_one_nanosecond_both_directions() {
    for exactly_at_edge in [
        "1970-01-01T00:05:00Z",
        "1969-12-31T23:55:00Z",
    ] {
        check(exactly_at_edge, 0, 300).expect("inclusive 300-second edge");
    }
    for one_nanosecond_beyond in [
        "1970-01-01T00:05:00.000000001Z",
        "1969-12-31T23:54:59.999999999Z",
    ] {
        assert!(matches!(
            check(one_nanosecond_beyond, 0, 300),
            Err(VerifyError::TimestampOutOfTolerance { tolerance_secs: 300, .. })
        ));
    }
    assert!(check("1970-01-01T00:00:00.000000001Z", 0, 0).is_err());
}

#[test]
fn forged_timestamp_invalid_calendar_and_signed_time_tampering_fail_closed() {
    let signed_time = "1970-01-01T00:00:00Z";
    let signature = sign(BODY, signed_time, WEBHOOK);
    let tampered = transmission("1970-01-01T00:00:01Z", &signature, CERT_URL);
    assert!(matches!(
        paypal::verify_at(&tampered, WEBHOOK, BODY, CERT, 1, 300),
        Err(VerifyError::SignatureMismatch)
    ));
    // A signature over a malformed time must never bypass strict parsing.
    for invalid_time in [
        "1970-01-01T00:00:00", "1970-01-01T00:00:00Ztrailing",
        "2026-02-29T00:00:00Z", "1970-01-01T00:00:60Z",
        "1970-01-01T00:00:00+24:00", "1970-01-01T00:00:00.0000000001Z",
    ] {
        let invalid_signature = sign(BODY, invalid_time, WEBHOOK);
        assert!(matches!(
            paypal::verify_at(
                &transmission(invalid_time, &invalid_signature, CERT_URL),
                WEBHOOK, BODY, CERT, 0, 300
            ),
            Err(VerifyError::InvalidInput(_))
        ));
    }
}

#[test]
fn huge_clock_skew_does_not_overflow_or_alias_a_valid_window() {
    let timestamp = "1970-01-01T00:00:00Z";
    for now in [i64::MIN, i64::MAX] {
        assert!(matches!(
            check(timestamp, now, 300),
            Err(VerifyError::TimestampOutOfTolerance { .. })
        ));
        // The full range is explicitly allowed; the RSA check still runs.
        check(timestamp, now, u64::MAX).expect("widened skew comparison");
    }
}

#[test]
fn legacy_signature_verification_is_not_misreported_as_freshness() {
    let timestamp = "1970-01-01T00:00:00Z";
    let signature = sign(BODY, timestamp, WEBHOOK);
    let trans = transmission(timestamp, &signature, CERT_URL);
    assert!(paypal::verify(&trans, WEBHOOK, BODY, CERT).is_ok());
    assert!(matches!(
        paypal::verify_at(&trans, WEBHOOK, BODY, CERT, 86_400, 300),
        Err(VerifyError::TimestampOutOfTolerance { .. })
    ));
}

#[test]
fn sixty_four_signed_refinements_require_all_six_authentication_gates() {
    const FULL: u8 = 0b11_1111;
    for bits in 0..=FULL {
        let config_ok = bits & (1 << 0) != 0;
        let envelope_ok = bits & (1 << 1) != 0;
        let provenance_ok = bits & (1 << 2) != 0;
        let signature_ok = bits & (1 << 3) != 0;
        let event_ok = bits & (1 << 4) != 0;
        let freshness_ok = bits & (1 << 5) != 0;

        let timestamp = if freshness_ok {
            "1970-01-01T00:00:00Z"
        } else {
            "1969-12-31T00:00:00Z"
        };
        let body = if event_ok { BODY } else { INVALID_EVENT };
        let signed_webhook = if signature_ok { WEBHOOK } else { "WH-OTHER" };
        let good_signature = sign(body, timestamp, signed_webhook);
        let sig = if envelope_ok { &good_signature } else { "not-base64" };
        let url = if provenance_ok { CERT_URL } else { "https://paypal.com.evil.test/cert.pem" };
        let configured_webhook = if config_ok { WEBHOOK } else { "" };
        let result = paypal::verify_at(
            &transmission(timestamp, sig, url),
            configured_webhook, body, CERT, 0, 300,
        );
        assert_eq!(
            result.is_ok(), bits == FULL,
            "signed PayPal six-gate mask {bits:#08b}: {result:?}"
        );
        if let Ok(event) = result {
            assert_eq!(event.provider, Provider::Paypal);
            assert_eq!(event.payload.as_slice(), BODY);
        }
    }
}
