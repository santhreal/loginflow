//! WebAuthn virtual authenticator drive implementation.
//!
//! Passwordless and second-factor WebAuthn challenges cannot be satisfied from
//! page JavaScript: `navigator.credentials.create/get` needs a real (or
//! virtual) authenticator. Chromium exposes a *virtual* authenticator through
//! the CDP `WebAuthn` domain, which is reachable only over the DevTools
//! protocol - never from injected script. This module enables that domain on a
//! live page and registers an authenticator built from
//! [`VirtualAuthenticatorConfig`], so a headless login drive can transparently
//! clear a WebAuthn step.

use crate::error::DriveError;
use runtime_headless::chromiumoxide::cdp::browser_protocol::web_authn::{
    AddVirtualAuthenticatorParams, AuthenticatorProtocol, AuthenticatorTransport, EnableParams,
    VirtualAuthenticatorOptions,
};
use runtime_headless::Page;

/// Configuration for the virtual authenticator.
#[derive(Debug, Clone)]
pub struct VirtualAuthenticatorConfig {
    /// The protocol to use: `"ctap2"` or `"u2f"`.
    pub protocol: String,
    /// The transport to simulate: `"usb"`, `"nfc"`, `"ble"`, `"cable"`, or `"internal"`.
    pub transport: String,
    /// Whether the authenticator supports resident keys (discoverable credentials).
    pub has_resident_key: bool,
    /// Whether the authenticator has a user verification mechanism.
    pub has_user_verification: bool,
}

impl Default for VirtualAuthenticatorConfig {
    fn default() -> Self {
        Self {
            protocol: "ctap2".to_string(),
            transport: "internal".to_string(),
            has_resident_key: true,
            has_user_verification: true,
        }
    }
}

impl VirtualAuthenticatorConfig {
    /// Translate the string-keyed config into typed CDP options, rejecting
    /// values Chromium does not accept (rather than silently defaulting).
    fn to_cdp_options(&self) -> Result<VirtualAuthenticatorOptions, DriveError> {
        let protocol = match self.protocol.trim().to_ascii_lowercase().as_str() {
            "ctap2" => AuthenticatorProtocol::Ctap2,
            "u2f" => AuthenticatorProtocol::U2f,
            other => {
                return Err(DriveError::Headless(format!(
                    "unsupported WebAuthn protocol {other:?}. Fix: use \"ctap2\" or \"u2f\""
                )))
            }
        };
        let transport = match self.transport.trim().to_ascii_lowercase().as_str() {
            "usb" => AuthenticatorTransport::Usb,
            "nfc" => AuthenticatorTransport::Nfc,
            "ble" => AuthenticatorTransport::Ble,
            "cable" => AuthenticatorTransport::Cable,
            "internal" => AuthenticatorTransport::Internal,
            other => {
                return Err(DriveError::Headless(format!(
                    "unsupported WebAuthn transport {other:?}. \
                     Fix: use one of usb|nfc|ble|cable|internal"
                )))
            }
        };

        let mut options = VirtualAuthenticatorOptions::new(protocol, transport);
        options.has_resident_key = Some(self.has_resident_key);
        options.has_user_verification = Some(self.has_user_verification);
        // Resolve user-presence and user-verification immediately, otherwise a
        // headless drive would hang waiting for a (non-existent) physical tap.
        options.automatic_presence_simulation = Some(true);
        options.is_user_verified = Some(self.has_user_verification);
        Ok(options)
    }
}

/// Drives a WebAuthn response by registering a CDP virtual authenticator.
///
/// Enables the `WebAuthn` CDP domain on `page` and adds a virtual authenticator
/// built from `config`. After this returns, any `navigator.credentials`
/// ceremony the page performs is satisfied by the synthetic authenticator with
/// no physical device. Returns the CDP authenticator id (useful for later
/// `removeVirtualAuthenticator` / credential inspection).
///
/// # Errors
///
/// Returns [`DriveError::Headless`] when the protocol/transport is unsupported,
/// or when the CDP `WebAuthn.enable` / `addVirtualAuthenticator` command fails
/// (for example, the page is not attached to a Chromium target).
pub async fn respond_to_webauthn_challenge(
    page: &Page,
    config: &VirtualAuthenticatorConfig,
) -> Result<String, DriveError> {
    if config.protocol.trim().is_empty() {
        return Err(DriveError::Headless(
            "protocol cannot be empty. Fix: set protocol to \"ctap2\" or \"u2f\"".to_string(),
        ));
    }
    let options = config.to_cdp_options()?;

    page.execute(EnableParams::default()).await.map_err(|e| {
        DriveError::Headless(format!(
            "failed to enable the WebAuthn CDP domain: {e}. \
             Fix: ensure the page is attached to a Chromium DevTools target"
        ))
    })?;

    let response = page
        .execute(AddVirtualAuthenticatorParams { options })
        .await
        .map_err(|e| {
            DriveError::Headless(format!(
                "failed to add the virtual authenticator: {e}. \
                 Fix: verify the protocol/transport combination is supported by this Chromium build"
            ))
        })?;

    Ok(response.result.authenticator_id.inner().clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_headless::chromiumoxide::cdp::browser_protocol::web_authn::{
        AuthenticatorProtocol, AuthenticatorTransport,
    };

    #[test]
    fn default_config_maps_to_ctap2_internal() {
        let opts = VirtualAuthenticatorConfig::default()
            .to_cdp_options()
            .expect("default config must be valid");
        assert_eq!(opts.protocol, AuthenticatorProtocol::Ctap2);
        assert_eq!(opts.transport, AuthenticatorTransport::Internal);
        assert_eq!(opts.has_resident_key, Some(true));
        assert_eq!(opts.has_user_verification, Some(true));
        // Headless drives must not block on a physical presence tap.
        assert_eq!(opts.automatic_presence_simulation, Some(true));
    }

    #[test]
    fn u2f_usb_maps_correctly_and_is_case_insensitive() {
        let cfg = VirtualAuthenticatorConfig {
            protocol: "U2F".to_string(),
            transport: "USB".to_string(),
            has_resident_key: false,
            has_user_verification: false,
        };
        let opts = cfg.to_cdp_options().expect("u2f/usb is valid");
        assert_eq!(opts.protocol, AuthenticatorProtocol::U2f);
        assert_eq!(opts.transport, AuthenticatorTransport::Usb);
        assert_eq!(opts.has_resident_key, Some(false));
        assert_eq!(opts.is_user_verified, Some(false));
    }

    #[test]
    fn every_transport_variant_maps() {
        for (name, want) in [
            ("usb", AuthenticatorTransport::Usb),
            ("nfc", AuthenticatorTransport::Nfc),
            ("ble", AuthenticatorTransport::Ble),
            ("cable", AuthenticatorTransport::Cable),
            ("internal", AuthenticatorTransport::Internal),
        ] {
            let cfg = VirtualAuthenticatorConfig {
                protocol: "ctap2".to_string(),
                transport: name.to_string(),
                has_resident_key: true,
                has_user_verification: true,
            };
            assert_eq!(
                cfg.to_cdp_options().unwrap().transport,
                want,
                "transport {name}"
            );
        }
    }

    #[test]
    fn unsupported_protocol_is_rejected_with_fix_hint() {
        let cfg = VirtualAuthenticatorConfig {
            protocol: "passkey".to_string(),
            ..VirtualAuthenticatorConfig::default()
        };
        let err = cfg.to_cdp_options().unwrap_err().to_string();
        assert!(err.contains("unsupported WebAuthn protocol"), "got: {err}");
        assert!(err.contains("Fix:"), "error must carry a Fix hint: {err}");
    }

    #[test]
    fn unsupported_transport_is_rejected_with_fix_hint() {
        let cfg = VirtualAuthenticatorConfig {
            transport: "lightning".to_string(),
            ..VirtualAuthenticatorConfig::default()
        };
        let err = cfg.to_cdp_options().unwrap_err().to_string();
        assert!(err.contains("unsupported WebAuthn transport"), "got: {err}");
        assert!(err.contains("Fix:"), "error must carry a Fix hint: {err}");
    }
}
