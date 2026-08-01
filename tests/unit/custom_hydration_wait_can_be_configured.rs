//! Unit tests for SPA hydration config.

#![cfg(feature = "browser")]
use std::time::Duration;

// Assumes the caller agent will export HydrationWait at the crate root or in `drive` module.
use loginflow::drive::HydrationWait;

#[test]
fn custom_hydration_wait_can_be_configured() {
    let config = HydrationWait {
        timeout: Duration::from_secs(30),
        selector: Some(".login-ready".to_string()),
        wait_for_idle: false,
    };

    assert_eq!(config.timeout, Duration::from_secs(30));
    assert_eq!(config.selector.as_deref(), Some(".login-ready"));
    assert!(!config.wait_for_idle);
}
