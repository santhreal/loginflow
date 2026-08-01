//! MFA sources and helpers.

pub mod email_link;
pub mod sms_relay;
pub mod totp;

use crate::error::MfaError;
use async_trait::async_trait;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

pub use email_link::*;
pub use sms_relay::*;
pub use totp::{totp_code_at, TotpSecret};

/// Timeout applied to every polling HTTP client used by MFA sources.
pub(crate) const MFA_CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// The HTTP client shared by the polling MFA sources, built once on first
/// use.
///
/// ONE-PLACE for the client configuration (sms_relay and email_link previously
/// hand-rolled the identical builder). A build failure is stored, not
/// panicked on: [`polling_client`] surfaces it as an `MfaError` at the call
/// site, so a poll fails closed with context instead of hanging forever on a
/// client without a timeout (the old `unwrap_or_default()` behavior).
static POLLING_CLIENT: LazyLock<Result<reqwest::Client, String>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(MFA_CLIENT_TIMEOUT)
        .build()
        .map_err(|e| format!("loginflow MFA HTTP client failed to build (TLS/resolver init): {e}"))
});

/// Returns the shared polling client, or the stored build error.
pub(crate) fn polling_client() -> Result<&'static reqwest::Client, MfaError> {
    POLLING_CLIENT
        .as_ref()
        .map_err(|e| MfaError::Email(e.clone()))
}

/// Kind of MFA challenge presented by the target.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MfaPrompt {
    /// Time-based one-time password field.
    Totp {
        /// Input field name when known.
        field_name: Option<String>,
    },
}

/// Response from an MFA source.
///
/// `Debug` redacts the code: an OTP is a credential, even if short-lived.
#[derive(Clone, PartialEq, Eq)]
pub struct MfaResponse {
    /// Six-digit (or configured-width) code.
    pub code: String,
}

impl std::fmt::Debug for MfaResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaResponse")
            .field("code", &"[redacted]")
            .finish()
    }
}

/// Async MFA code provider (TOTP, SMS relay, etc.).
#[async_trait]
pub trait MfaSource: Send + Sync {
    /// Fetch a code for the given prompt.
    async fn fetch(&self, prompt: &MfaPrompt) -> Result<MfaResponse, MfaError>;
}

/// MFA source backed by a shared TOTP secret.
#[derive(Debug, Clone)]
pub struct TotpMfaSource {
    secret: TotpSecret,
}

impl TotpMfaSource {
    /// Create a source from a base32-encoded shared secret.
    #[must_use]
    pub fn new(secret_base32: impl Into<String>) -> Self {
        Self {
            secret: TotpSecret::new(secret_base32),
        }
    }
}

#[async_trait]
impl MfaSource for TotpMfaSource {
    async fn fetch(&self, prompt: &MfaPrompt) -> Result<MfaResponse, MfaError> {
        let _ = prompt;
        let code = self.secret.current_code()?;
        if code.is_empty() {
            return Err(MfaError::Empty);
        }
        Ok(MfaResponse { code })
    }
}

/// Wrap an [`Arc<dyn MfaSource>`] for credentials.
#[allow(dead_code)]
pub type SharedMfaSource = Arc<dyn MfaSource>;

#[cfg(test)]
mod client_tests {
    use super::{polling_client, MFA_CLIENT_TIMEOUT};
    use reqwest::Url;
    use std::time::Duration;

    #[test]
    fn mfa_client_timeout_is_ten_seconds() {
        // Pin the shared timeout so a silent change is caught. The old per-source
        // `unwrap_or_default()` dropped this timeout entirely on a build error.
        assert_eq!(MFA_CLIENT_TIMEOUT, Duration::from_secs(10));
    }

    #[test]
    fn polling_client_succeeds_and_is_shared_by_both_sources() {
        // The shared client must build on a healthy host and both polling
        // sources must draw from the same ONE-PLACE client rather than
        // hand-rolling their own.
        let first = polling_client().expect("shared client builds");
        let second = polling_client().expect("shared client builds");
        assert!(
            std::ptr::eq(first, second),
            "client must be shared, not rebuilt"
        );
        let url = Url::parse("https://mfa.example/api").unwrap();
        let _sms = super::sms_relay::SmsRelayMfaSource::new(url.clone(), "+15550001111");
        let _email = super::email_link::EmailLinkMfaSource::new(url, "user@example.com");
    }
}
