//! Adversarial and malformed inputs for WebAuthn endpoints.

// Assuming the main agent will wire up `pub mod webauthn` in `discover/mod.rs`
use loginflow::discover::webauthn::discover_webauthn_challenge;

#[test]
fn discover_js_obfuscation() {
    // If the JS is heavily obfuscated, our simple substring match might fail.
    // This documents the current limitation.
    let html = "<script>window['navigator']['credentials']['create']({});</script>";
    let challenge = discover_webauthn_challenge("https://example.com/login", html)
        .expect("Fix: Provide valid test HTML");

    // Currently, our stub doesn't detect this.
    assert!(challenge.is_none());
}
