//! CLI credentials + session export contracts.

use loginflow::ScaldAuth;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct CredentialsFile {
    username: String,
    password: String,
    totp_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionExport {
    session_name: String,
    domain: String,
    scald_auth: ScaldAuth,
}

#[test]
fn loginflow_builder_accepts_captcha_solver() {
    let solver = std::sync::Arc::new(loginflow::StubCaptchaSolver::new("tok"));
    let driver = loginflow::LoginFlowBuilder::default()
        .with_captcha_solver(solver)
        .build()
        .expect("build");
    let _ = driver;
}

#[tokio::test]
async fn captured_session_has_non_empty_cookies_after_http_style_capture() {
    let mut session = authjar::AuthSession::new("u");
    session.add_cookie("session", "abc", "127.0.0.1");
    let captured =
        loginflow::capture_from_auth_session(session, "127.0.0.1", vec![]).expect("capture");
    assert!(!captured.scald_auth.cookies.is_empty());
}
