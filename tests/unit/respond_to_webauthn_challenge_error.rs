#![cfg(feature = "browser")]
//! Unit tests for WebAuthn discovery and drive.
//!
//! Regression: this test was written against a stub API that validated a
//! session string. The real drive validates the authenticator configuration
//! before touching the page; an empty protocol must fail with a descriptive
//! error instead of reaching the CDP layer. The validation runs before any
//! page I/O, but the public entry point still takes a page, so the test uses
//! a live browser when one is available.

use loginflow::drive::webauthn::{respond_to_webauthn_challenge, VirtualAuthenticatorConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respond_to_webauthn_challenge_error() {
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

    let config = VirtualAuthenticatorConfig {
        protocol: String::new(),
        ..Default::default()
    };
    let result = respond_to_webauthn_challenge(&page, &config).await;
    let error = result.expect_err("an empty protocol must be rejected");
    assert!(
        error.to_string().contains("protocol cannot be empty"),
        "unexpected error: {error}"
    );
}
