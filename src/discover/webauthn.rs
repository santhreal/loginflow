//! WebAuthn challenge discovery.

use crate::error::DiscoverError;

/// A discovered WebAuthn challenge endpoint or configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnChallenge {
    /// The URL where the challenge was found.
    pub url: String,
    /// Indicates whether the challenge is for registration or authentication.
    pub is_registration: bool,
}

/// Scans HTML content for WebAuthn challenge indicators.
pub fn discover_webauthn_challenge(
    url: &str,
    html: &str,
) -> Result<Option<WebAuthnChallenge>, DiscoverError> {
    if html.is_empty() {
        return Err(DiscoverError::Parse("empty html document".to_string()));
    }

    let is_registration = html.contains("navigator.credentials.create");
    let is_authentication = html.contains("navigator.credentials.get");

    if is_registration || is_authentication {
        Ok(Some(WebAuthnChallenge {
            url: url.to_string(),
            is_registration,
        }))
    } else {
        Ok(None)
    }
}
