//! Unit tests for WebAuthn discovery and drive.

use loginflow::discover::webauthn::discover_webauthn_challenge;

#[test]
fn discover_webauthn_registration() {
    let html = r#"
        <script>
            navigator.credentials.create({
                publicKey: {
                    challenge: new Uint8Array([1, 2, 3]),
                    rp: { name: "Example" },
                    user: { id: new Uint8Array([1]), name: "user", displayName: "User" },
                    pubKeyCredParams: [{ type: "public-key", alg: -7 }]
                }
            });
        </script>
    "#;

    let challenge = discover_webauthn_challenge("https://example.com/register", html)
        .expect("Fix: Provide valid test HTML")
        .expect("Fix: Challenge should be found in test HTML");

    assert!(challenge.is_registration);
    assert_eq!(challenge.url, "https://example.com/register");
}
