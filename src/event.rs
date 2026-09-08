//! The result of a *successful* verification: the provider event, already
//! proven authentic, with the two fields the billing webhook ledger keys on
//! (`billing_webhook_events.provider_event_id` + `event_type`).

use crate::provider::Provider;

/// A webhook whose provider-specific signature verification succeeded. The only
/// way to obtain one is through a verifier, so holding a `VerifiedEvent` proves
/// that the exact bytes in [`Self::payload`] passed that provider's configured
/// authentication checks.
///
/// Stripe verification also enforces the caller-supplied replay-tolerance
/// window. The current PayPal verifier cryptographically binds
/// `transmission_time` but does not yet parse or age-check it; that distinct
/// freshness hardening is tracked in issue #9. Callers must additionally apply
/// durable provider-event identity plus payload-digest idempotency before
/// causing billing effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvent {
    pub provider: Provider,
    /// The provider's unique event id (Stripe `evt_…`, PayPal `WH-…`). Maps to
    /// `billing_webhook_events.provider_event_id`; the downstream ledger uses
    /// it together with provider identity and the authenticated payload digest
    /// to distinguish an identical redelivery from conflicting identity reuse.
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
