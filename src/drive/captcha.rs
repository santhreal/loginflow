//! Captcha gate dispatch - trait + stub; optional captchaforge integration.

use async_trait::async_trait;
use thiserror::Error;

/// Captcha variety detected on a login page.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaptchaKind {
    /// Google reCAPTCHA v2 checkbox / invisible.
    RecaptchaV2,
    /// Cloudflare Turnstile.
    Turnstile,
    /// hCaptcha.
    HCaptcha,
    /// Unknown vendor-specific challenge.
    Unknown(String),
}

/// Challenge handed to a [`CaptchaSolver`].
#[derive(Debug, Clone)]
pub struct CaptchaChallenge {
    /// Page URL where the gate was detected.
    pub page_url: String,
    /// Detected captcha kind.
    pub kind: CaptchaKind,
}

/// Solution token or bypass proof from a solver.
///
/// `Debug` redacts the token: it is a bearer proof accepted by the target
/// site and must not leak into logs.
#[derive(Clone, PartialEq, Eq)]
pub struct CaptchaSolution {
    /// Vendor response token or typed answer.
    pub token: String,
    /// Whether the solver considers the gate cleared.
    pub solved: bool,
}

impl std::fmt::Debug for CaptchaSolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaSolution")
            .field("token", &"[redacted]")
            .field("solved", &self.solved)
            .finish()
    }
}

/// Captcha solver failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaptchaError {
    /// Solver declined or failed.
    #[error("captcha solve failed: {0}")]
    SolveFailed(String),
    /// Browser page required (captchaforge path).
    #[error("captcha solve requires browser page")]
    NeedsBrowser,
    /// captchaforge returned no result.
    #[error("captchaforge returned no solution")]
    NoSolution,
}

/// Async captcha solver (captchaforge, stub, or third-party).
#[async_trait]
pub trait CaptchaSolver: Send + Sync {
    /// Produce a solution for `challenge`.
    async fn solve(&self, challenge: &CaptchaChallenge) -> Result<CaptchaSolution, CaptchaError>;
}

/// Deterministic stub for tests and offline flows.
#[derive(Debug, Clone)]
pub struct StubCaptchaSolver {
    token: String,
}

impl StubCaptchaSolver {
    /// Always return `token` with `solved = true`.
    #[must_use]
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}

#[async_trait]
impl CaptchaSolver for StubCaptchaSolver {
    async fn solve(&self, challenge: &CaptchaChallenge) -> Result<CaptchaSolution, CaptchaError> {
        let _ = challenge;
        Ok(CaptchaSolution {
            token: self.token.clone(),
            solved: true,
        })
    }
}

/// Invoke captchaforge's `auto_solve` path when the `captchaforge` feature is enabled.
///
/// # Errors
///
/// Returns [`CaptchaError`] when the solve chain fails or returns no token.
#[cfg(all(feature = "browser", feature = "captchaforge"))]
pub async fn solve_via_captchaforge(
    page: &runtime_headless::Page,
    challenge: &CaptchaChallenge,
) -> Result<CaptchaSolution, CaptchaError> {
    use captchaforge::solver::CaptchaSolveResult;

    let _ = challenge;
    let result = captchaforge::auto_solve(page)
        .await
        .map_err(|e| CaptchaError::SolveFailed(e.to_string()))?;

    let Some(CaptchaSolveResult {
        solution, success, ..
    }) = result
    else {
        return Err(CaptchaError::NoSolution);
    };

    if !success || solution.is_empty() {
        return Err(CaptchaError::SolveFailed(
            "captchaforge reported unsuccessful solve".into(),
        ));
    }

    Ok(CaptchaSolution {
        token: solution,
        solved: true,
    })
}

/// Bridge: Captcha solving primitives - integrates with captchaforge when a page handle exists.
#[cfg(all(feature = "browser", feature = "captchaforge"))]
#[derive(Debug, Default)]
pub struct CaptchaForgeSolver;

#[cfg(all(feature = "browser", feature = "captchaforge"))]
#[async_trait]
impl CaptchaSolver for CaptchaForgeSolver {
    async fn solve(&self, _challenge: &CaptchaChallenge) -> Result<CaptchaSolution, CaptchaError> {
        Err(CaptchaError::NeedsBrowser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_solver_returns_configured_token() {
        let solver = StubCaptchaSolver::new("test-token-xyz");
        let solution = solver
            .solve(&CaptchaChallenge {
                page_url: "https://app.example/login".into(),
                kind: CaptchaKind::RecaptchaV2,
            })
            .await
            .expect("solve");
        assert!(solution.solved);
        assert_eq!(solution.token, "test-token-xyz");
    }

    #[tokio::test]
    async fn stub_solver_ignores_challenge_kind() {
        let solver = StubCaptchaSolver::new("tok");
        let solution = solver
            .solve(&CaptchaChallenge {
                page_url: "https://x.test/".into(),
                kind: CaptchaKind::Unknown("custom".into()),
            })
            .await
            .expect("solve");
        assert_eq!(solution.token, "tok");
    }
}
