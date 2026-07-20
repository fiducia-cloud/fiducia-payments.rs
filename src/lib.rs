//! Provider-agnostic payment logic for fiducia.cloud.
//!
//! Scope is deliberately narrow: **verify inbound provider webhooks** and hand
//! back an authenticated [`VerifiedEvent`]. It owns no HTTP server and no
//! database — the customer backend mounts the routes and writes the billing
//! tables (`fiducia-interfaces` `sql/customer.sql`). Keeping the security-
//! critical crypto here, pure and time-injected, lets it be exhaustively
//! unit-tested without a network, a clock, or a running Postgres.
//!
//! ```no_run
//! use fiducia_payments::{stripe, VerifiedEvent};
//! # fn h(body: &[u8], sig: &str, secret: &str, now: i64) -> Result<VerifiedEvent, fiducia_payments::VerifyError> {
//! let event = stripe::verify(body, sig, secret, now, stripe::DEFAULT_TOLERANCE_SECS)?;
//! // event.id -> billing_webhook_events.provider_event_id (unique => idempotent)
//! # Ok(event) }
//! ```

mod error;
mod event;
mod provider;

pub mod paypal;
pub mod stripe;

pub use error::VerifyError;
pub use event::VerifiedEvent;
pub use provider::{Provider, UnknownProvider};
