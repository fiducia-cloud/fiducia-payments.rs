//! PayPal webhook signature verification (offline).
//!
//! PayPal does not HMAC the body. Each webhook carries these headers:
//!
//! ```text
//! paypal-transmission-id:   <uuid>
//! paypal-transmission-time: <rfc3339>
//! paypal-transmission-sig:  <base64 RSA signature>
//! paypal-cert-url:          https://api.paypal.com/.../cert.pem
//! paypal-auth-algo:         SHA256withRSA
//! ```
//!
//! The signed message is NOT the body but a CRC32-bound digest of it:
//!
//! ```text
//! {transmission_id}|{transmission_time}|{webhook_id}|{crc32(raw_body)}
//! ```
//!
//! where `crc32` is the unsigned 32-bit CRC of the raw body as a decimal string,
//! and `webhook_id` is the id PayPal assigned this endpoint (server config, NOT
//! from the request). Verification is RSA-SHA256 (PKCS#1 v1.5) of that message
//! against the public key in the certificate at `paypal-cert-url`.
//! Reference: https://developer.paypal.com/api/rest/webhooks/rest/#verify-webhook-signature-manually
//!
//! Fetching the certificate is a network operation and therefore the caller's
//! job (it should also cache and pin it); this module owns the two things that
//! must be exactly right and are pure: (1) building the signed message, and
//! (2) the RSA verification against a supplied certificate — plus the fail-closed
//! check that the cert URL is actually a PayPal host.

use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;
use spki::DecodePublicKey;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

use crate::error::VerifyError;
use crate::event::VerifiedEvent;
use crate::provider::Provider;

/// The transmission headers PayPal sends alongside a webhook. The caller reads
/// these off the request; `webhook_id` and `cert_pem` come from server config
/// and the (cached) cert fetch respectively.
#[derive(Debug, Clone)]
pub struct Transmission<'a> {
    pub transmission_id: &'a str,
    pub transmission_time: &'a str,
    /// base64 of the RSA signature (`paypal-transmission-sig`).
    pub signature_b64: &'a str,
    /// `paypal-cert-url`. Validated to be a PayPal host before use.
    pub cert_url: &'a str,
    /// `paypal-auth-algo`; must be `SHA256withRSA`.
    pub auth_algo: &'a str,
}

/// Build the exact message PayPal signs: `id|time|webhook_id|crc32(body)`.
///
/// Public + pure so it can be tested directly and reused by a caller that does
/// the RSA step with its own key material.
pub fn signed_message(
    transmission_id: &str,
    transmission_time: &str,
    webhook_id: &str,
    raw_body: &[u8],
) -> String {
    let crc = crc32fast::hash(raw_body);
    format!("{transmission_id}|{transmission_time}|{webhook_id}|{crc}")
}

/// Reject a cert URL that is not served by PayPal. Without this an attacker could
/// present a validly-signed message under *their own* cert and pass RSA
/// verification. Only `*.paypal.com` over HTTPS, with no embedded credentials.
///
/// Public so a caller can gate on it BEFORE fetching the certificate — fetching
/// an attacker-controlled `paypal-cert-url` would be an SSRF. `verify` re-checks
/// it regardless, as defense in depth.
///
/// This MUST parse the URL exactly the way the fetching HTTP client does. An
/// earlier hand-split on `[':', '/']` was bypassable: `https://api.paypal.com:x@evil.com/`
/// has authority `api.paypal.com:x@evil.com`, whose real host is `evil.com`
/// (the part before the port/path is *userinfo*), yet a naive split sees
/// `api.paypal.com` and passes. Userinfo (`@`), backslashes, `?` and `#` all
/// terminate or reshape the authority — so we let the `url` crate find the host.
pub fn cert_url_is_paypal(cert_url: &str) -> bool {
    let Ok(url) = url::Url::parse(cert_url) else {
        return false;
    };
    // HTTPS only, and refuse any embedded credentials outright: a URL with
    // userinfo is never a shape PayPal emits and is the classic host-confusion
    // vector.
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.host_str() {
        Some(host) => {
            let host = host.to_ascii_lowercase();
            host == "paypal.com" || host.ends_with(".paypal.com")
        }
        None => false,
    }
}

/// Verify a PayPal webhook and return the authenticated event.
///
/// * `t`         — the transmission headers.
/// * `webhook_id`— the endpoint's PayPal webhook id (server config).
/// * `raw_body`  — the RAW request body bytes.
/// * `cert_pem`  — the PEM X.509 certificate fetched from `t.cert_url` (the
///   caller fetches/caches it; we re-validate the URL host here as defense in
///   depth so a mismatched cert can't slip through).
pub fn verify(
    t: &Transmission<'_>,
    webhook_id: &str,
    raw_body: &[u8],
    cert_pem: &str,
) -> Result<VerifiedEvent, VerifyError> {
    if !t.auth_algo.eq_ignore_ascii_case("SHA256withRSA") {
        return Err(VerifyError::InvalidInput(format!(
            "unsupported auth algo: {}",
            t.auth_algo
        )));
    }
    if !cert_url_is_paypal(t.cert_url) {
        return Err(VerifyError::InvalidInput(format!(
            "cert url is not a PayPal host: {}",
            t.cert_url
        )));
    }
    if webhook_id.is_empty() {
        return Err(VerifyError::InvalidInput("empty webhook id".into()));
    }

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(t.signature_b64.trim())
        .map_err(|_| VerifyError::MalformedSignature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| VerifyError::MalformedSignature)?;

    let public_key = rsa_public_key_from_cert(cert_pem)?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let message = signed_message(t.transmission_id, t.transmission_time, webhook_id, raw_body);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| VerifyError::SignatureMismatch)?;

    VerifiedEvent::from_body(Provider::Paypal, raw_body)
}

/// Extract the RSA public key from a PEM X.509 certificate.
fn rsa_public_key_from_cert(cert_pem: &str) -> Result<RsaPublicKey, VerifyError> {
    let cert = Certificate::from_pem(cert_pem.as_bytes())
        .map_err(|e| VerifyError::InvalidInput(format!("certificate not valid PEM/DER: {e}")))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| VerifyError::InvalidInput(format!("cannot re-encode SPKI: {e}")))?;
    RsaPublicKey::from_public_key_der(&spki_der)
        .map_err(|e| VerifyError::InvalidInput(format!("certificate is not an RSA key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;

    // A real self-signed RSA cert + its PKCS#8 key, generated once with openssl
    // and embedded, so the RSA path (including production cert parsing) runs
    // end-to-end offline with no network and no keygen cost.
    const TEST_CERT_PEM: &str = include_str!("../tests/fixtures/paypal_test_cert.pem");
    const TEST_KEY_PEM: &str = include_str!("../tests/fixtures/paypal_test_key.pem");

    fn test_signing_key() -> SigningKey<Sha256> {
        let private = RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM).expect("load test key");
        SigningKey::<Sha256>::new(private)
    }

    fn sign_b64(message: &str) -> String {
        let sig = test_signing_key().sign(message.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    #[test]
    fn signed_message_is_crc32_bound() {
        // Message shape and CRC are exact; a changed body changes the CRC.
        let m = signed_message("tid", "2024-01-01T00:00:00Z", "WH-1", b"{}");
        assert!(m.starts_with("tid|2024-01-01T00:00:00Z|WH-1|"));
        let other = signed_message("tid", "2024-01-01T00:00:00Z", "WH-1", b"{ }");
        assert_ne!(m, other, "different bodies must yield different messages");
    }

    #[test]
    fn cert_host_gate() {
        assert!(cert_url_is_paypal(
            "https://api.paypal.com/v1/notifications/certs/cert.pem"
        ));
        assert!(cert_url_is_paypal(
            "https://api.sandbox.paypal.com/certs/x.pem"
        ));
        assert!(!cert_url_is_paypal("http://api.paypal.com/x.pem")); // not https
        assert!(!cert_url_is_paypal("https://paypal.com.evil.test/x.pem")); // suffix trick
        assert!(!cert_url_is_paypal("https://notpaypal.com/x.pem"));
    }

    #[test]
    fn verifies_a_valid_paypal_signature_and_rejects_tampering() {
        let webhook_id = "WH-TEST";
        let body = br#"{"id":"WH-evt-1","event_type":"PAYMENT.CAPTURE.COMPLETED"}"#;
        let tid = "trans-123";
        let ttime = "2024-06-01T12:00:00Z";
        let sig_b64 = sign_b64(&signed_message(tid, ttime, webhook_id, body));

        let t = Transmission {
            transmission_id: tid,
            transmission_time: ttime,
            signature_b64: &sig_b64,
            cert_url: "https://api.paypal.com/v1/notifications/certs/CERT.pem",
            auth_algo: "SHA256withRSA",
        };

        let event = verify(&t, webhook_id, body, TEST_CERT_PEM).expect("valid signature verifies");
        assert_eq!(event.provider, Provider::Paypal);
        assert_eq!(event.id, "WH-evt-1");
        assert_eq!(event.event_type, "PAYMENT.CAPTURE.COMPLETED");

        // Tamper the body: CRC changes, signature no longer matches.
        let tampered = br#"{"id":"WH-evt-1","event_type":"PAYMENT.CAPTURE.DENIED"}"#;
        assert!(matches!(
            verify(&t, webhook_id, tampered, TEST_CERT_PEM).unwrap_err(),
            VerifyError::SignatureMismatch
        ));

        // Wrong webhook_id (server config mismatch) also fails.
        assert!(matches!(
            verify(&t, "WH-OTHER", body, TEST_CERT_PEM).unwrap_err(),
            VerifyError::SignatureMismatch
        ));
    }

    #[test]
    fn rejects_non_paypal_cert_url_before_crypto() {
        let t = Transmission {
            transmission_id: "x",
            transmission_time: "t",
            signature_b64: "AAAA",
            cert_url: "https://evil.test/cert.pem",
            auth_algo: "SHA256withRSA",
        };
        assert!(matches!(
            verify(&t, "WH", b"{}", TEST_CERT_PEM).unwrap_err(),
            VerifyError::InvalidInput(_)
        ));
    }

    #[test]
    fn rejects_wrong_auth_algo() {
        let t = Transmission {
            transmission_id: "x",
            transmission_time: "t",
            signature_b64: "AAAA",
            cert_url: "https://api.paypal.com/c.pem",
            auth_algo: "HMACSHA256",
        };
        assert!(matches!(
            verify(&t, "WH", b"{}", TEST_CERT_PEM).unwrap_err(),
            VerifyError::InvalidInput(_)
        ));
    }
}
