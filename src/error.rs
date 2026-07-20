//! One error type for both providers' verification paths. Every variant is a
//! REJECTION — a verifier returns `Ok(VerifiedEvent)` only when the signature is
//! valid and fresh, so a caller can treat any `Err` as "do not trust this body".

/// Why a webhook failed verification. Deliberately coarse in its public
/// `Display` (an attacker probing the endpoint learns only "rejected"), while
/// the variant carries enough detail for server-side logs.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The provider signature header was absent.
    #[error("missing signature header")]
    MissingSignature,

    /// The signature header was present but not in the provider's expected shape
    /// (e.g. Stripe's `t=...,v1=...`), so no candidate signature could be read.
    #[error("malformed signature header")]
    MalformedSignature,

    /// The signed timestamp is outside the allowed tolerance window — a replay
    /// of an old (even once-valid) event. Carries the skew for logging.
    #[error("timestamp outside tolerance ({skew_secs}s > {tolerance_secs}s)")]
    TimestampOutOfTolerance { skew_secs: i64, tolerance_secs: u64 },

    /// No provided signature matched the recomputed one. The catch-all for a
    /// forged body, a wrong secret, or a tampered payload.
    #[error("signature mismatch")]
    SignatureMismatch,

    /// A configuration/input value was itself invalid (empty secret, unparseable
    /// certificate, non-PayPal cert host, …) — the request could not even be
    /// evaluated, which is still a fail-closed rejection.
    #[error("verification input invalid: {0}")]
    InvalidInput(String),

    /// The verified body was not the JSON shape an event requires.
    #[error("event body malformed: {0}")]
    MalformedEvent(String),
}
