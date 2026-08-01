//! GET a canary URL and assert status/body markers.

use crate::capture::ScaldAuth;
use crate::error::VerifyError;
use crate::http_identity::{self, HttpIdentity};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, COOKIE};
use std::time::Duration;

/// Configuration for post-login canary checks.
#[derive(Debug, Clone)]
pub struct CanaryConfig {
    /// Absolute URL to GET after login.
    pub url: String,
    /// Acceptable HTTP status codes (default `[200]`).
    pub expected_status: Vec<u16>,
    /// Substrings that must appear in the response body.
    pub body_markers: Vec<String>,
    /// Request timeout.
    pub timeout: Duration,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            expected_status: vec![200],
            body_markers: Vec::new(),
            timeout: Duration::from_secs(15),
        }
    }
}

/// GET the canary URL using captured session cookies/headers.
///
/// # Errors
///
/// Returns [`VerifyError`] when the request fails or assertions do not hold.
pub async fn verify_canary(auth: &ScaldAuth, config: &CanaryConfig) -> Result<(), VerifyError> {
    verify_canary_with_identity(auth, config, HttpIdentity::None, false).await
}

pub(crate) async fn verify_canary_with_identity(
    auth: &ScaldAuth,
    config: &CanaryConfig,
    identity: HttpIdentity,
    insecure: bool,
) -> Result<(), VerifyError> {
    if config.url.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(config.timeout)
        .redirect(reqwest::redirect::Policy::limited(5))
        .danger_accept_invalid_certs(insecure)
        .build()
        .map_err(|e| VerifyError::Request(e.to_string()))?;

    let mut headers = HeaderMap::new();
    if !auth.cookies.is_empty() {
        let cookie_val = auth.cookies.join("; ");
        let value =
            HeaderValue::from_str(&cookie_val).map_err(|e| VerifyError::Request(e.to_string()))?;
        headers.insert(COOKIE, value);
    }
    for (name, value) in &auth.headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| VerifyError::Request(e.to_string()))?;
        let value =
            HeaderValue::from_str(value).map_err(|e| VerifyError::Request(e.to_string()))?;
        headers.insert(name, value);
    }
    http_identity::apply_to_header_map(&mut headers, identity).map_err(VerifyError::Request)?;

    let response = client
        .get(&config.url)
        .headers(headers)
        .send()
        .await
        .map_err(|e| VerifyError::Request(e.to_string()))?;

    let status = response.status().as_u16();
    if !config.expected_status.contains(&status) {
        return Err(VerifyError::Status {
            actual: status,
            expected: config.expected_status.clone(),
        });
    }

    let body = response
        .text()
        .await
        .map_err(|e| VerifyError::Request(e.to_string()))?;

    let missing: Vec<String> = config
        .body_markers
        .iter()
        .filter(|m| !body.contains(m.as_str()))
        .cloned()
        .collect();

    if !missing.is_empty() {
        return Err(VerifyError::BodyMarkers { missing });
    }

    Ok(())
}

#[cfg(all(test, feature = "stealth"))]
mod tests {
    use super::*;
    use guise::{ProfileBundle, StealthProfile};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn captured_header<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
        raw.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    #[tokio::test]
    async fn canary_with_stealth_identity_sends_profile_headers_and_auth() {
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
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("server should respond");
            String::from_utf8(request).expect("request should be utf8")
        });

        let auth = ScaldAuth {
            cookies: vec!["sid=abc".to_string()],
            headers: vec![("X-CSRF-Token".to_string(), "tok".to_string())],
        };
        let config = CanaryConfig {
            url: format!("http://{addr}/canary"),
            expected_status: vec![200],
            body_markers: vec!["ok".to_string()],
            timeout: Duration::from_secs(5),
        };

        verify_canary_with_identity(
            &auth,
            &config,
            HttpIdentity::Stealth(ProfileBundle::for_browser(StealthProfile::FirefoxWindows)),
            false,
        )
        .await
        .expect("canary should pass");

        let raw_request = server.await.expect("server task should finish");
        let facts = guise::fingerprint::profile_facts(StealthProfile::FirefoxWindows);
        assert_eq!(
            captured_header(&raw_request, "User-Agent"),
            Some(facts.user_agent)
        );
        assert_eq!(
            captured_header(&raw_request, "Accept-Language"),
            Some(facts.accept_language)
        );
        assert_eq!(captured_header(&raw_request, "Cookie"), Some("sid=abc"));
        assert_eq!(captured_header(&raw_request, "X-CSRF-Token"), Some("tok"));
        assert_eq!(captured_header(&raw_request, "Accept-Encoding"), None);
    }
}
