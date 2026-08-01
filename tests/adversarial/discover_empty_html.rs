//! Adversarial and malformed inputs for WebAuthn endpoints.

// Assuming the main agent will wire up `pub mod webauthn` in `discover/mod.rs`
use loginflow::discover::webauthn::discover_webauthn_challenge;

#[test]
fn discover_empty_html() {
    let result = discover_webauthn_challenge("https://example.com/login", "");
    assert!(result.is_err());
    // Error is DiscoverError::Parse which maps to parsing failed
}
