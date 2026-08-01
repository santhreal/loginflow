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
fn session_json_roundtrip_scald_auth() {
    let mut session = authjar::AuthSession::new("cli-test");
    session.add_cookie("sid", "v1", "app.example");
    let captured =
        loginflow::capture_from_auth_session(session, "app.example", vec![]).expect("capture");

    let export = SessionExport {
        session_name: captured.auth_session.name.clone(),
        domain: "app.example".into(),
        scald_auth: captured.scald_auth.clone(),
    };
    let json = serde_json::to_string(&export).expect("serialize");
    let back: SessionExport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.scald_auth, captured.scald_auth);
}
