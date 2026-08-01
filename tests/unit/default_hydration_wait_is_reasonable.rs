//! Unit tests for SPA hydration config.

#![cfg(feature = "browser")]
use std::time::Duration;

// Assumes the caller agent will export HydrationWait at the crate root or in `drive` module.
use loginflow::drive::HydrationWait;

#[test]
fn default_hydration_wait_is_reasonable() {
    let config = HydrationWait::default();
    assert_eq!(config.timeout, Duration::from_secs(10));
    assert!(config.selector.is_none());
    assert!(config.wait_for_idle);
}
