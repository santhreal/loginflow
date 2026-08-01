//! Wait for single-page app (SPA) hydration.

use crate::error::DriveError;
use runtime_headless::{
    evaluate_script_value, wait_for_ready_state, wait_for_visible, HeadlessError, Page,
};
use std::time::Duration;

/// Configuration for waiting on SPA hydration.
#[derive(Debug, Clone)]
pub struct HydrationWait {
    /// How long to wait for the hydration signal.
    pub timeout: Duration,
    /// Optional CSS selector that indicates the SPA has hydrated.
    pub selector: Option<String>,
    /// Whether to wait for `requestIdleCallback` (network/CPU idle).
    pub wait_for_idle: bool,
}

impl Default for HydrationWait {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            selector: None,
            wait_for_idle: true,
        }
    }
}

/// Wait for a single-page app to finish hydration.
///
/// This checks `document.readyState`, optionally waits for a specific
/// DOM selector to become visible, and optionally waits for main thread idle.
///
/// # Errors
///
/// Returns a [`DriveError::Headless`] if the wait times out or the browser
/// connection fails.
pub async fn wait_for_spa_hydration(page: &Page, config: &HydrationWait) -> Result<(), DriveError> {
    wait_for_ready_state(page, config.timeout)
        .await
        .map_err(|source: HeadlessError| DriveError::Headless(source.to_string()))?;

    if let Some(selector) = &config.selector {
        wait_for_visible(page, selector, config.timeout)
            .await
            .map_err(|source: HeadlessError| DriveError::Headless(source.to_string()))?;
    }

    if config.wait_for_idle {
        let idle_script = r#"
            async () => {
                return new Promise(resolve => {
                    if ('requestIdleCallback' in window) {
                        window.requestIdleCallback(() => resolve("idle"), { timeout: 2000 });
                    } else {
                        setTimeout(() => resolve("timeout"), 500);
                    }
                });
            }
        "#;
        // We ignore script failure here because not all pages support requestIdleCallback,
        // and evaluate_script_value might fail if the page is navigating.
        let _ = evaluate_script_value(page, idle_script).await;

        // Ensure pending DOM updates have flushed. Instead of a blind fixed
        // sleep (which paid a flat 100ms even when nothing was pending), await
        // the browser committing a frame: a double `requestAnimationFrame`
        // resolves only after style+layout for the pending mutations have been
        // painted. That returns near-instantly when the DOM is already settled
        // and at most one frame otherwise, so an immediate page is no longer
        // penalised. Bounded by the hydration timeout so a navigating/hung page
        // cannot block us.
        const DOM_FLUSH_SCRIPT: &str = r#"
            async () => {
                return new Promise(resolve => {
                    requestAnimationFrame(() => requestAnimationFrame(() => resolve("flushed")));
                });
            }
        "#;
        let flushed = await_dom_flush(
            evaluate_script_value(page, DOM_FLUSH_SCRIPT),
            config.timeout,
        )
        .await;
        if !flushed {
            // Best-effort flush: a navigating page or an eval error means we
            // could not confirm the frame committed. Surface it (never a silent
            // swallow) and proceed, matching the idle-wait's best-effort model.
            tracing::debug!("SPA hydration DOM flush did not confirm before timeout; proceeding");
        }
    }

    Ok(())
}

/// Await a DOM-flush future, bounded by `timeout`. Returns `true` iff the flush
/// resolved successfully within the budget, `false` if it timed out or the
/// underlying evaluation failed.
///
/// This is the timing core of the hydration flush, factored out so it is
/// deterministically testable without a live browser: an already-settled page
/// (an immediately-ready future) returns at once with no fixed floor, while a
/// hung page is bounded by `timeout`.
async fn await_dom_flush<T, E>(
    flush: impl std::future::Future<Output = Result<T, E>>,
    timeout: Duration,
) -> bool {
    matches!(tokio::time::timeout(timeout, flush).await, Ok(Ok(_)))
}

#[cfg(test)]
mod tests {
    use super::await_dom_flush;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn await_dom_flush_returns_immediately_when_dom_is_settled() {
        // An already-settled page resolves its flush future at once. The wait
        // must impose NO fixed floor (the old code always slept 100ms), so an
        // immediate flush completes in well under that.
        let start = Instant::now();
        let flushed = await_dom_flush(async { Ok::<(), ()>(()) }, Duration::from_secs(5)).await;
        let elapsed = start.elapsed();
        assert!(flushed, "a ready flush must report success");
        assert!(
            elapsed < Duration::from_millis(50),
            "an immediate DOM flush must not pay the old fixed 100ms floor, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn await_dom_flush_is_bounded_by_timeout_when_flush_hangs() {
        // A navigating/hung page never resolves the flush future; the wait must
        // be bounded by the timeout and report non-completion, not hang.
        let start = Instant::now();
        let flushed = await_dom_flush(
            std::future::pending::<Result<(), ()>>(),
            Duration::from_millis(80),
        )
        .await;
        let elapsed = start.elapsed();
        assert!(
            !flushed,
            "a hung flush must time out and report non-completion"
        );
        assert!(
            elapsed >= Duration::from_millis(80),
            "must wait out the timeout budget, waited only {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "must not hang far past the timeout, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn await_dom_flush_reports_failure_when_eval_errors() {
        // If the browser eval itself errors (page navigating), the flush is not
        // confirmed — report false so the caller logs and proceeds, never a
        // silent success.
        let flushed = await_dom_flush(async { Err::<(), ()>(()) }, Duration::from_secs(5)).await;
        assert!(!flushed, "an errored flush must report non-completion");
    }
}
