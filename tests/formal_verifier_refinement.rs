//! Production refinement checks for `formal/provider_verification.qnt`.
//!
//! The tests enumerate every combination of the five modeled verification
//! gates for each provider and drive the public verifier APIs with real
//! HMAC/RSA operations. A combination succeeds if and only if all gates hold.

use base64::Engine;
use fiducia_payments::{paypal, stripe, Provider};
use hmac::{Hmac, Mac};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const STRIPE_SECRET: &str = "whsec_formal_refinement";
const STRIPE_TIMESTAMP: i64 = 1_700_000_000;
const STRIPE_TOLERANCE: u64 = 300;
const STRIPE_VALID_BODY: &[u8] = br#"{"id":"evt_formal","type":"invoice.paid"}"#;
const STRIPE_INVALID_EVENT_BODY: &[u8] = br#"{"id":"evt_formal"}"#;

const PAYPAL_WEBHOOK_ID: &str = "WH-FORMAL";
const PAYPAL_VALID_BODY: &[u8] = br#"{"id":"WH-formal","event_type":"PAYMENT.CAPTURE.COMPLETED"}"#;
const PAYPAL_INVALID_EVENT_BODY: &[u8] = br#"{"id":"WH-formal"}"#;
const PAYPAL_CERT_PEM: &str = include_str!("fixtures/paypal_test_cert.pem");
const PAYPAL_KEY_PEM: &str = include_str!("fixtures/paypal_test_key.pem");

fn stripe_header(body: &[u8], secret: &str, timestamp: i64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("valid HMAC key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!(
        "t={timestamp},v1={}",
        hex::encode(mac.finalize().into_bytes())
    )
}

fn paypal_signature(body: &[u8], webhook_id: &str) -> String {
    let private = RsaPrivateKey::from_pkcs8_pem(PAYPAL_KEY_PEM).expect("load non-secret test key");
    let signing = SigningKey::<Sha256>::new(private);
    let message = paypal::signed_message(
        "transmission-formal",
        "2026-09-08T12:00:00Z",
        webhook_id,
        body,
    );
    base64::engine::general_purpose::STANDARD.encode(signing.sign(message.as_bytes()).to_bytes())
}

#[test]
fn stripe_refines_all_five_authentication_gates() {
    const ALL_VALID: u8 = 0b1_1111;

    for mask in 0_u8..=ALL_VALID {
        let configuration_valid = mask & (1 << 0) != 0;
        let envelope_valid = mask & (1 << 1) != 0;
        let provenance_valid = mask & (1 << 2) != 0;
        let signature_valid = mask & (1 << 3) != 0;
        let event_valid = mask & (1 << 4) != 0;

        let body = if event_valid {
            STRIPE_VALID_BODY
        } else {
            STRIPE_INVALID_EVENT_BODY
        };
        let signing_secret = if signature_valid {
            STRIPE_SECRET
        } else {
            "whsec_wrong"
        };
        let header = if envelope_valid {
            stripe_header(body, signing_secret, STRIPE_TIMESTAMP)
        } else {
            "not-a-stripe-signature-header".to_owned()
        };
        let verification_secret = if configuration_valid {
            STRIPE_SECRET
        } else {
            ""
        };
        let now = if provenance_valid {
            STRIPE_TIMESTAMP
        } else {
            STRIPE_TIMESTAMP + STRIPE_TOLERANCE as i64 + 1
        };

        let result = stripe::verify(body, &header, verification_secret, now, STRIPE_TOLERANCE);
        assert_eq!(
            result.is_ok(),
            mask == ALL_VALID,
            "Stripe gate mask {mask:#07b} produced {result:?}"
        );

        if let Ok(event) = result {
            assert_eq!(event.provider, Provider::Stripe);
            assert_eq!(event.id, "evt_formal");
            assert_eq!(event.event_type, "invoice.paid");
            assert_eq!(event.payload.as_slice(), body);
        }
    }
}

#[test]
fn paypal_refines_all_five_authentication_gates() {
    const ALL_VALID: u8 = 0b1_1111;

    for mask in 0_u8..=ALL_VALID {
        let configuration_valid = mask & (1 << 0) != 0;
        let envelope_valid = mask & (1 << 1) != 0;
        let provenance_valid = mask & (1 << 2) != 0;
        let signature_valid = mask & (1 << 3) != 0;
        let event_valid = mask & (1 << 4) != 0;

        let body = if event_valid {
            PAYPAL_VALID_BODY
        } else {
            PAYPAL_INVALID_EVENT_BODY
        };
        let signed_body = if signature_valid {
            body
        } else if event_valid {
            PAYPAL_INVALID_EVENT_BODY
        } else {
            PAYPAL_VALID_BODY
        };
        let webhook_id = if configuration_valid {
            PAYPAL_WEBHOOK_ID
        } else {
            ""
        };
        let signature = if envelope_valid {
            paypal_signature(signed_body, PAYPAL_WEBHOOK_ID)
        } else {
            "not-base64".to_owned()
        };
        let transmission = paypal::Transmission {
            transmission_id: "transmission-formal",
            transmission_time: "2026-09-08T12:00:00Z",
            signature_b64: &signature,
            cert_url: if provenance_valid {
                "https://api.paypal.com/v1/notifications/certs/formal.pem"
            } else {
                "https://paypal.com.attacker.example/formal.pem"
            },
            auth_algo: "SHA256withRSA",
        };

        let result = paypal::verify(&transmission, webhook_id, body, PAYPAL_CERT_PEM);
        assert_eq!(
            result.is_ok(),
            mask == ALL_VALID,
            "PayPal gate mask {mask:#07b} produced {result:?}"
        );

        if let Ok(event) = result {
            assert_eq!(event.provider, Provider::Paypal);
            assert_eq!(event.id, "WH-formal");
            assert_eq!(event.event_type, "PAYMENT.CAPTURE.COMPLETED");
            assert_eq!(event.payload.as_slice(), body);
        }
    }
}

#[test]
fn signed_paypal_time_is_bound_but_current_verifier_does_not_claim_freshness() {
    let signature = paypal_signature(PAYPAL_VALID_BODY, PAYPAL_WEBHOOK_ID);
    let transmission = paypal::Transmission {
        transmission_id: "transmission-formal",
        transmission_time: "2026-09-08T12:00:00Z",
        signature_b64: &signature,
        cert_url: "https://api.paypal.com/v1/notifications/certs/formal.pem",
        auth_algo: "SHA256withRSA",
    };

    let event = paypal::verify(
        &transmission,
        PAYPAL_WEBHOOK_ID,
        PAYPAL_VALID_BODY,
        PAYPAL_CERT_PEM,
    )
    .expect("correctly signed fixture verifies");

    assert_eq!(event.payload.as_slice(), PAYPAL_VALID_BODY);
    assert_ne!(
        paypal::signed_message(
            "transmission-formal",
            "2026-09-08T12:00:01Z",
            PAYPAL_WEBHOOK_ID,
            PAYPAL_VALID_BODY,
        ),
        paypal::signed_message(
            "transmission-formal",
            transmission.transmission_time,
            PAYPAL_WEBHOOK_ID,
            PAYPAL_VALID_BODY,
        ),
        "transmission time must remain cryptographically bound"
    );
}
