//! The result of a *successful* verification: the provider event, already
//! proven authentic, with the two fields the billing webhook ledger keys on
//! (`billing_webhook_events.provider_event_id` + `event_type`).

use crate::provider::Provider;

/// A webhook whose signature has been verified. The only way to obtain one is
/// through a verifier, so holding a `VerifiedEvent` is proof the bytes are
/// authentic and fresh — the type makes "did you check the signature?"
/// unrepresentable-if-forgotten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvent {
    pub provider: Provider,
    /// The provider's unique event id (Stripe `evt_…`, PayPal `WH-…`). Maps to
    /// `billing_webhook_events.provider_event_id`; the unique index there makes
    /// processing idempotent under provider redelivery.
    pub id: String,
    /// The provider event type (`invoice.paid`, `PAYMENT.CAPTURE.COMPLETED`, …).
    pub event_type: String,
    /// The exact verified bytes. Callers hash these into
    /// `billing_webhook_events.payload_sha256` and parse the typed payload from
    /// here — never from a re-read of the request body, which was not verified.
    pub payload: Vec<u8>,
}

impl VerifiedEvent {
    /// Extract `id` and `type` from a provider event body. Both providers put an
    /// `id` and a `type` at the top level of the JSON, so one extractor serves
    /// both; the caller supplies which `Provider` was verified.
    pub(crate) fn from_body(
        provider: Provider,
        payload: &[u8],
    ) -> Result<Self, crate::VerifyError> {
        let value: serde_json::Value = serde_json::from_slice(payload)
            .map_err(|e| crate::VerifyError::MalformedEvent(format!("not JSON: {e}")))?;
        let id = value
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::VerifyError::MalformedEvent("missing string `id`".into()))?;
        let event_type = value
            .get("type")
            // PayPal uses `event_type`; Stripe uses `type`. Accept either.
            .or_else(|| value.get("event_type"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| crate::VerifyError::MalformedEvent("missing string `type`".into()))?;
        Ok(VerifiedEvent {
            provider,
            id: id.to_string(),
            event_type: event_type.to_string(),
            payload: payload.to_vec(),
        })
    }
}
