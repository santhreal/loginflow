//! RFC 6238 TOTP from a shared base32 secret.

use crate::error::MfaError;
use base32::Alphabet;
use totp_lite::{totp_custom, Sha1};

const TIME_STEP_SECS: u64 = 30;
const CODE_DIGITS: u32 = 6;

/// Shared TOTP secret (base32).
///
/// The secret is a long-lived credential: `Debug` is redacted and the stored
/// bytes are zeroized on drop so they do not linger in freed memory.
#[derive(Clone)]
pub struct TotpSecret {
    secret_base32: String,
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpSecret")
            .field("secret_base32", &"[redacted]")
            .finish()
    }
}

impl Drop for TotpSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.secret_base32);
    }
}

impl TotpSecret {
    /// Wrap a base32 secret string.
    #[must_use]
    pub fn new(secret_base32: impl Into<String>) -> Self {
        Self {
            secret_base32: secret_base32.into(),
        }
    }

    /// Current TOTP code for the system clock.
    ///
    /// # Errors
    ///
    /// Returns [`MfaError::Totp`] when the secret or clock is invalid.
    pub fn current_code(&self) -> Result<String, MfaError> {
        let step = current_time_step()?;
        totp_code_at(&self.secret_base32, step)
    }
}

/// Compute a TOTP code for an explicit time step (for deterministic tests).
///
/// # Errors
///
/// Returns [`MfaError::Totp`] on decode failure.
pub fn totp_code_at(secret_base32: &str, time_step: u64) -> Result<String, MfaError> {
    let clean_secret: String = secret_base32
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .trim_end_matches('=')
        .to_uppercase();

    let key = base32::decode(Alphabet::Rfc4648 { padding: false }, &clean_secret)
        .ok_or_else(|| MfaError::Totp("invalid base32 secret".into()))?;

    let code = totp_custom::<Sha1>(TIME_STEP_SECS, CODE_DIGITS, &key, time_step);
    Ok(format!("{code:0width$}", width = CODE_DIGITS as usize))
}

fn current_time_step() -> Result<u64, MfaError> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| MfaError::Totp(e.to_string()))?;
    Ok(now.as_secs() / TIME_STEP_SECS)
}
