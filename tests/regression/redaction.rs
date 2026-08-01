//! Regression: credential redaction in Debug output.
//!
//! Several credential-bearing types derived `Debug`, so any `{:?}` or
//! `tracing` capture printed bearer secrets (TOTP seeds, JWTs, OTP codes,
//! captcha tokens, session cookies) into logs. These tests lock the redaction
//! in place: the secret material must never appear in Debug output, while
//! non-secret metadata stays visible for diagnostics.

use loginflow::capture::jwt::Jwt;
use loginflow::drive::CaptchaSolution;
use loginflow::mfa::{MfaResponse, TotpSecret};
use loginflow::ScaldAuth;

#[test]
fn totp_secret_debug_is_redacted() {
    let secret = TotpSecret::new("JBSWY3DPEHPK3PXP");
    let dbg = format!("{secret:?}");
    assert!(!dbg.contains("JBSWY3DPEHPK3PXP"), "TOTP seed leaked: {dbg}");
    assert!(dbg.contains("[redacted]"));
}

#[test]
fn jwt_debug_redacts_raw_token() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let jwt = Jwt::decode(token).expect("valid JWT decodes");
    let dbg = format!("{jwt:?}");
    assert!(
        !dbg.contains("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        "raw JWT leaked: {dbg}"
    );
    assert!(dbg.contains("[redacted]"));
    // The payload is not secret material once decoded; it stays visible.
    assert!(dbg.contains("1234567890"));
}

#[test]
fn mfa_response_debug_redacts_code() {
    let response = MfaResponse {
        code: "482910".to_string(),
    };
    let dbg = format!("{response:?}");
    assert!(!dbg.contains("482910"), "OTP code leaked: {dbg}");
    assert!(dbg.contains("[redacted]"));
}

#[test]
fn captcha_solution_debug_redacts_token() {
    let solution = CaptchaSolution {
        token: "03AFcWeA5-secret".to_string(),
        solved: true,
    };
    let dbg = format!("{solution:?}");
    assert!(
        !dbg.contains("03AFcWeA5-secret"),
        "captcha token leaked: {dbg}"
    );
    assert!(dbg.contains("[redacted]"));
    assert!(dbg.contains("solved: true"));
}

#[test]
fn scald_auth_debug_redacts_cookie_and_header_values() {
    let auth = ScaldAuth {
        cookies: vec![
            "sid=supersecretvalue".to_string(),
            "theme=light".to_string(),
        ],
        headers: vec![(
            "Authorization".to_string(),
            "Bearer hunter2-secret".to_string(),
        )],
    };
    let dbg = format!("{auth:?}");
    assert!(
        !dbg.contains("supersecretvalue"),
        "cookie value leaked: {dbg}"
    );
    assert!(
        !dbg.contains("hunter2-secret"),
        "header value leaked: {dbg}"
    );
    // Names stay visible so logs remain diagnosable.
    assert!(dbg.contains("sid"));
    assert!(dbg.contains("Authorization"));
}
