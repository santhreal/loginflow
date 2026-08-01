//! Adversarial and malformed inputs for WebAuthn endpoints.

// Assuming the main agent will wire up `pub mod webauthn` in `discover/mod.rs`
use loginflow::discover::webauthn::discover_webauthn_challenge;

#[test]
fn discover_webauthn_malformed_html() {
    // Should gracefully handle broken HTML since we only do substring checks currently
    let html = "<div class='test'><script>navigator.credentials.create({</script>";
    let challenge = discover_webauthn_challenge("https://example.com/login", html)
        .expect("Fix: Provide valid test HTML");

    // We expect it to find the substring
    assert!(challenge.is_some());
    let challenge = challenge.expect("Fix: Substring logic should have found the match");
    assert!(challenge.is_registration);
}
