//! Captcha solver trait dispatch.

use loginflow::{CaptchaChallenge, CaptchaKind, CaptchaSolver, StubCaptchaSolver};
use std::sync::Arc;

#[tokio::test]
async fn stub_solver_via_trait_object() {
    let solver: Arc<dyn CaptchaSolver> =
        Arc::new(StubCaptchaSolver::new("g-recaptcha-response-token"));
    let solution = solver
        .solve(&CaptchaChallenge {
            page_url: "https://login.example/".into(),
            kind: CaptchaKind::RecaptchaV2,
        })
        .await
        .expect("solve");
    assert!(solution.solved);
    assert!(solution.token.starts_with("g-recaptcha"));
}

#[tokio::test]
async fn turnstile_kind_accepted_by_stub() {
    let solver = StubCaptchaSolver::new("cf-turnstile-token");
    let solution = solver
        .solve(&CaptchaChallenge {
            page_url: "https://gate.example/".into(),
            kind: CaptchaKind::Turnstile,
        })
        .await
        .expect("solve");
    assert_eq!(solution.token, "cf-turnstile-token");
}

#[tokio::test]
async fn unknown_kind_still_solved_by_stub() {
    let solver = StubCaptchaSolver::new("custom");
    let solution = solver
        .solve(&CaptchaChallenge {
            page_url: "https://x.test/".into(),
            kind: CaptchaKind::Unknown("vendor-x".into()),
        })
        .await
        .expect("solve");
    assert_eq!(solution.token, "custom");
}
