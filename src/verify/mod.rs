//! Post-login verification.

mod canary;

pub(crate) use canary::verify_canary_with_identity;
pub use canary::{verify_canary, CanaryConfig};
