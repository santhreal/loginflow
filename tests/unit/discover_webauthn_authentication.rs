//! Unit tests for WebAuthn discovery and drive.

use loginflow::discover::webauthn::discover_webauthn_challenge;

#[test]
fn discover_webauthn_authentication() {
    let html = r#"
        <script>
            navigator.credentials.get({
                publicKey: {
                    challenge: new Uint8Array([1, 2, 3])
                }
            });
        </script>
    "#;

    let challenge = discover_webauthn_challenge("https://example.com/login", html)
        .expect("Fix: Provide valid test HTML")
        .expect("Fix: Challenge should be found in test HTML");

    assert!(!challenge.is_registration);
    assert_eq!(challenge.url, "https://example.com/login");
}
