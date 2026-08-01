//! scald `LoginFlow` HTTP fast-path when discovery marks form simple.

use loginflow::{discover_best_login_form, perform_http_login, LoginFlowBuilder, ScaldLoginFlow};
use secrecy::SecretString;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

const LOGIN_HTML: &str = r#"
<form action="/login" method="post">
  <input type="hidden" name="csrf" value="abc" />
  <input type="text" name="user" />
  <input type="password" name="pass" />
</form>
"#;

async fn spawn_mock_login_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let body_ok = req.contains("user=alice") && req.contains("pass=secret");
            let response = if body_ok {
                "HTTP/1.1 200 OK\r\nSet-Cookie: session=logged-in; Path=/; HttpOnly\r\nContent-Length: 2\r\n\r\nok"
            } else {
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
            };
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn http_fastpath_sets_session_cookie() {
    let origin = spawn_mock_login_server().await;
    let base = Url::parse(&origin).expect("url");
    let form = discover_best_login_form(LOGIN_HTML, &base)
        .expect("discover")
        .expect("form");
    assert!(form.http_simple);

    let flow = ScaldLoginFlow::from_discovered(
        &form,
        "alice",
        &SecretString::from("secret".to_string()),
        None,
    );
    let captured = perform_http_login(&flow, &[], &base, Duration::from_secs(5))
        .await
        .expect("login");
    assert!(
        captured
            .scald_auth
            .cookies
            .iter()
            .any(|c| c.contains("session=logged-in")),
        "cookies: {:?}",
        captured.scald_auth.cookies
    );
}

#[tokio::test]
async fn loginflow_uses_http_when_form_is_simple() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 8192];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let response = if req.starts_with("GET ") {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    LOGIN_HTML.len(),
                    LOGIN_HTML
                )
            } else if req.contains("user=alice") && req.contains("pass=secret") {
                "HTTP/1.1 200 OK\r\nSet-Cookie: session=flow; Path=/\r\nContent-Length: 0\r\n\r\n"
                    .to_string()
            } else {
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_string()
            };
            let _ = socket.write_all(response.as_bytes()).await;
        }
    });

    let target = Url::parse(&format!("http://{addr}/")).expect("url");
    let driver = LoginFlowBuilder::default()
        .prefer_http(true)
        .http_timeout(Duration::from_secs(5))
        .build()
        .expect("build");
    let creds = loginflow::Credentials {
        username: "alice".into(),
        password: SecretString::from("secret".to_string()),
        mfa_source: None,
    };
    let captured = driver.login(&target, &creds).await.expect("login");
    assert!(captured
        .scald_auth
        .cookies
        .iter()
        .any(|c| c.contains("session=flow")));
}

#[tokio::test]
async fn http_fastpath_error_does_not_leak_password() {
    // Use a port that is very unlikely to be listening so the request fails
    // at the transport layer, then prove the error string does not contain
    // the password value. This is a regression guard on the
    // `password.expose_secret().to_string()` fast path.
    let password = "hunter2_leak_probe_2026";
    let flow = ScaldLoginFlow {
        url: "http://127.0.0.1:1/login".to_string(),
        method: "POST".to_string(),
        fields: vec![
            ("user".to_string(), "alice".to_string()),
            ("pass".to_string(), password.to_string()),
        ],
    };
    let origin = Url::parse("http://127.0.0.1:1/").expect("url");

    let err = perform_http_login(&flow, &[], &origin, Duration::from_secs(2))
        .await
        .expect_err("connection to port 1 should fail");

    let err_text = format!("{err}");
    assert!(
        !err_text.contains(password),
        "HTTP login error must not contain the password: {err_text}"
    );
    assert!(
        !err_text.contains("hunter2"),
        "HTTP login error must not contain any password substring: {err_text}"
    );
}
