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
fn credentials_toml_parses_username_password_and_totp() {
    let raw = r#"
username = "alice"
password = "s3cret"
totp_secret = "JBSWY3DPEHPK3PXP"
"#;
    let creds: CredentialsFile = toml::from_str(raw).expect("parse");
    assert_eq!(creds.username, "alice");
    assert_eq!(creds.password, "s3cret");
    assert_eq!(creds.totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
}
