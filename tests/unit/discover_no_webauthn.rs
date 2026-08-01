//! Unit tests for WebAuthn discovery and drive.

use loginflow::discover::webauthn::discover_webauthn_challenge;

#[test]
fn discover_no_webauthn() {
    let html = "<html><body><p>No webauthn here</p></body></html>";
    let challenge = discover_webauthn_challenge("https://example.com/login", html)
        .expect("Fix: Provide valid test HTML");
    assert!(challenge.is_none());
}
