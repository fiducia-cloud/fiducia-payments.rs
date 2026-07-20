//! The payment providers fiducia supports. The string forms match the
//! `provider` CHECK constraint on the billing tables in fiducia-interfaces
//! `sql/customer.sql`, so a value stored in `billing_webhook_events.provider`
//! round-trips through this enum.

use std::fmt;
use std::str::FromStr;

/// A supported payment provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    Stripe,
    Paypal,
}

impl Provider {
    /// The wire/DB string, identical to the SQL CHECK constraint values.
    pub const fn as_str(self) -> &'static str {
        match self {
            Provider::Stripe => "stripe",
            Provider::Paypal => "paypal",
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsing is case-insensitive on input but only accepts the two known values,
/// so an unexpected provider name fails closed rather than defaulting.
impl FromStr for Provider {
    type Err = UnknownProvider;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stripe" => Ok(Provider::Stripe),
            "paypal" => Ok(Provider::Paypal),
            _ => Err(UnknownProvider(s.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown payment provider: {0:?}")]
pub struct UnknownProvider(pub String);
