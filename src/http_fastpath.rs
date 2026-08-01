//! scald-compatible HTTP form POST fast path (no browser).

use crate::capture::{capture_from_http_headers, CapturedSession};
use crate::discover::DiscoveredForm;
use crate::error::HttpLoginError;
use crate::http_identity::{self, HttpIdentity};
use reqwest::cookie::{CookieStore, Jar};
use reqwest::redirect::Policy;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// scald `LoginFlow` wire shape (forward/back compat).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaldLoginFlow {
    /// Form action URL.
    pub url: String,
    /// HTTP method (`GET` or `POST`).
    pub method: String,
    /// Field name/value pairs.
    pub fields: Vec<(String, String)>,
}

impl ScaldLoginFlow {
    /// Build from a discovered form and credentials.
    #[must_use]
    pub fn from_discovered(
        form: &DiscoveredForm,
        username: &str,
        password: &SecretString,
        mfa_code: Option<&str>,
    ) -> Self {
        let mut fields = Vec::new();
        for (name, value) in &form.csrf_fields {
            fields.push((name.clone(), value.clone()));
        }
        for (name, value) in &form.extra_hidden {
            fields.push((name.clone(), value.clone()));
        }
        fields.push((form.username_field.clone(), username.to_string()));
        fields.push((
            form.password_field.clone(),
            password.expose_secret().to_string(),
        ));
        if let Some(code) = mfa_code {
            fields.push(("otp".to_string(), code.to_string()));
        }
        Self {
            url: form.action_url.clone(),
            method: form.method.as_str().to_string(),
            fields,
        }
    }
}

/// Execute HTTP login using scald-identical semantics.
///
/// # Errors
///
/// Returns [`HttpLoginError`] on transport failure or empty cookie jar.
pub async fn perform_http_login(
    flow: &ScaldLoginFlow,
    seed_cookies: &[String],
    target_origin: &Url,
    timeout: Duration,
) -> Result<CapturedSession, HttpLoginError> {
    perform_http_login_with_identity(
        flow,
        seed_cookies,
        target_origin,
        timeout,
        HttpIdentity::None,
        false,
    )
    .await
}

pub(crate) async fn perform_http_login_with_identity(
    flow: &ScaldLoginFlow,
    seed_cookies: &[String],
    target_origin: &Url,
    timeout: Duration,
    identity: HttpIdentity,
    insecure: bool,
) -> Result<CapturedSession, HttpLoginError> {
    let jar = Arc::new(Jar::default());
    let seed_url = target_origin.clone();
    for cookie in seed_cookies {
        jar.add_cookie_str(cookie, &seed_url);
    }

    let client_builder = reqwest::Client::builder()
        .cookie_provider(jar.clone())
        .redirect(Policy::limited(10))
        .timeout(timeout)
        .danger_accept_invalid_certs(insecure);

    if insecure {
        tracing::warn!(
            "TLS certificate verification disabled for credential submission to {}",
            target_origin
        );
    }
    let client_builder = http_identity::apply_to_client_builder(client_builder, identity)
        .map_err(HttpLoginError::Transport)?;
    let client = client_builder
        .build()
        .map_err(|e| HttpLoginError::Transport(e.to_string()))?;

    let url = Url::parse(&flow.url).map_err(|e| HttpLoginError::Transport(e.to_string()))?;

    let response = if flow.method.eq_ignore_ascii_case("GET") {
        client.get(url).query(&flow.fields).send().await
    } else {
        client.post(url).form(&flow.fields).send().await
    }
    .map_err(|e| HttpLoginError::Transport(e.to_string()))?;

    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let header_refs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let body = response
        .text()
        .await
        .map_err(|e| HttpLoginError::Transport(e.to_string()))?;

    let domain = target_origin
        .host_str()
        .ok_or(HttpLoginError::MissingHost)?;
    let captured = capture_from_http_headers("loginflow", domain, status, &header_refs, &body)
        .map_err(|e| HttpLoginError::Transport(e.to_string()))?;

    if captured.scald_auth.cookies.is_empty() {
        // Harvest jar for target origin like scald perform_login
        if let Some(header) = jar.cookies(target_origin) {
            if let Ok(s) = header.to_str() {
                let cookies: Vec<String> = s
                    .split(';')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect();
                if !cookies.is_empty() {
                    let mut session = captured.auth_session.clone();
                    for part in &cookies {
                        if let Some((name, value)) = part.split_once('=') {
                            session.add_cookie(name.trim(), value.trim(), domain);
                        }
                    }
                    return crate::capture::capture_from_auth_session(
                        session,
                        domain,
                        captured.scald_auth.headers.clone(),
                    )
                    .map_err(|e| HttpLoginError::Transport(e.to_string()));
                }
            }
        }
        return Err(HttpLoginError::NoCookies);
    }

    Ok(captured)
}

/// Whether a discovered form should use the HTTP fast path.
#[must_use]
pub fn eligible_for_http_fastpath(form: &DiscoveredForm, use_browser: bool) -> bool {
    form.http_simple && !use_browser
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discover::discover_best_login_form;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn scald_flow_from_discovered_fields() {
        let html = r#"<form action="/login" method="post">
            <input type="hidden" name="csrf" value="t" />
            <input name="user" type="text" />
            <input name="pass" type="password" />
        </form>"#;
        let page = Url::parse("https://app.test/").expect("url");
        let form = discover_best_login_form(html, &page)
            .expect("ok")
            .expect("form");
        let flow = ScaldLoginFlow::from_discovered(
            &form,
            "alice",
            &SecretString::from("secret".to_string()),
            None,
        );
        assert_eq!(flow.method, "POST");
        assert!(flow.fields.iter().any(|(k, _)| k == "user"));
        assert!(flow
            .fields
            .iter()
            .any(|(k, v)| k == "pass" && v == "secret"));
    }

    #[tokio::test]
    async fn self_signed_cert_is_rejected_by_default() {
        let (url, _cert) = spawn_https_mock_login_server().await;
        let origin = Url::parse(&url).expect("url");
        let flow = ScaldLoginFlow {
            url: format!("{url}/login"),
            method: "POST".to_string(),
            fields: vec![("user".to_string(), "alice".to_string())],
        };
        let err = perform_http_login_with_identity(
            &flow,
            &[],
            &origin,
            Duration::from_secs(5),
            HttpIdentity::None,
            false,
        )
        .await
        .expect_err("default must reject invalid TLS certificate");
        assert!(matches!(err, HttpLoginError::Transport(_)));
        assert!(
            err.to_string().contains("https://localhost"),
            "expected transport error for the invalid-cert host, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn self_signed_cert_is_accepted_when_insecure() {
        let (url, _cert) = spawn_https_mock_login_server().await;
        let origin = Url::parse(&url).expect("url");
        let flow = ScaldLoginFlow {
            url: format!("{url}/login"),
            method: "POST".to_string(),
            fields: vec![("user".to_string(), "alice".to_string())],
        };
        let captured = perform_http_login_with_identity(
            &flow,
            &[],
            &origin,
            Duration::from_secs(5),
            HttpIdentity::None,
            true,
        )
        .await
        .expect("insecure=true must accept invalid TLS certificate");
        assert_eq!(captured.scald_auth.cookies, vec!["sid=server"]);
    }

    async fn spawn_https_mock_login_server() -> (String, rustls::pki_types::CertificateDer<'static>)
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = rustls::pki_types::CertificateDer::from(cert.cert);
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(socket).await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=server; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });
        (format!("https://localhost:{}", addr.port()), certificate)
    }
}

#[cfg(all(test, feature = "stealth"))]
mod stealth_identity_tests {
    use super::*;
    use crate::http_identity::HttpIdentity;
    use guise::{ProfileBundle, StealthProfile};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn captured_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
        raw.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    #[tokio::test]
    async fn http_login_with_stealth_identity_sends_profile_headers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have addr");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("server should accept");
            let mut request = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                let n = socket.read(&mut buf).await.expect("server should read");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=server; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("server should respond");
            String::from_utf8(request).expect("request should be utf8")
        });

        let target_origin = Url::parse(&format!("http://{addr}/")).expect("url");
        let flow = ScaldLoginFlow {
            url: format!("http://{addr}/login"),
            method: "POST".to_string(),
            fields: vec![("user".to_string(), "alice".to_string())],
        };
        let captured = perform_http_login_with_identity(
            &flow,
            &[],
            &target_origin,
            Duration::from_secs(5),
            HttpIdentity::Stealth(ProfileBundle::for_browser(StealthProfile::FirefoxWindows)),
            false,
        )
        .await
        .expect("login should capture cookie");
        assert_eq!(captured.scald_auth.cookies, vec!["sid=server"]);

        let raw_request = server.await.expect("server task should finish");
        let facts = guise::fingerprint::profile_facts(StealthProfile::FirefoxWindows);
        assert_eq!(
            captured_header(&raw_request, "User-Agent"),
            Some(facts.user_agent)
        );
        assert_eq!(captured_header(&raw_request, "Accept"), Some(facts.accept));
        assert_eq!(
            captured_header(&raw_request, "Accept-Language"),
            Some(facts.accept_language)
        );
        assert_eq!(captured_header(&raw_request, "Accept-Encoding"), None);
    }
}
