#![cfg(feature = "browser")]
//! Unit tests for WebAuthn discovery and drive.
//!
//! Regression: this test was written against a stub API that took a session
//! string and returned a constant. The real drive registers a CDP virtual
//! authenticator on a live page and returns its authenticator id. The test
//! now proves that contract against real Chromium when one is available.

use loginflow::drive::webauthn::{respond_to_webauthn_challenge, VirtualAuthenticatorConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_to_webauthn_challenge_success() {
    if !runtime_headless::is_browser_available() {
        return;
    }
    let options = runtime_headless::BrowserLaunchOptions::default_stealth();
    let runtime = runtime_headless::BrowserRuntime::launch(&options)
        .await
        .expect("launch headless chromium");
    let page = runtime
        .browser()
        .new_page("about:blank")
        .await
        .expect("open blank page");

    let config = VirtualAuthenticatorConfig::default();
    let authenticator_id = respond_to_webauthn_challenge(&page, &config)
        .await
        .expect("virtual authenticator registration must succeed on a live page");

    assert!(
        !authenticator_id.is_empty(),
        "the CDP authenticator id must not be empty"
    );
}
