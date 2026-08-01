//! Follow OAuth / SSO HTTP redirect chains (mock-friendly, no browser required).

use crate::error::DriveError;
use crate::http_identity::{self, HttpIdentity};
use reqwest::header::{HeaderMap, LOCATION};
use reqwest::redirect::Policy;
use std::time::Duration;
use url::Url;

/// One hop in an OAuth redirect chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectHop {
    /// Request URL for this hop.
    pub from_url: String,
    /// HTTP status (302, 303, …).
    pub status: u16,
    /// `Location` header when present.
    pub location: Option<String>,
}

/// Result of walking a redirect chain to completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthChainResult {
    /// Ordered redirect hops (excludes the terminal non-redirect response).
    pub hops: Vec<RedirectHop>,
    /// Final URL after redirects.
    pub final_url: String,
    /// Aggregated `Set-Cookie` name/value pairs from all hops.
    pub cookies: Vec<(String, String)>,
    /// Terminal HTTP status.
    pub final_status: u16,
}

/// Build a redirect-tracing HTTP client (manual redirect follow).
pub fn oauth_redirect_client(timeout: Duration) -> Result<reqwest::Client, DriveError> {
    oauth_redirect_client_with_identity(timeout, HttpIdentity::None)
}

pub(crate) fn oauth_redirect_client_with_identity(
    timeout: Duration,
    identity: HttpIdentity,
) -> Result<reqwest::Client, DriveError> {
    let client_builder = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(timeout)
        .danger_accept_invalid_certs(true);
    let client_builder = http_identity::apply_to_client_builder(client_builder, identity)
        .map_err(DriveError::OAuth)?;
    client_builder
        .build()
        .map_err(|e| DriveError::OAuth(e.to_string()))
}

/// Follow an OAuth redirect chain up to `max_hops`.
///
/// # Errors
///
/// Returns [`DriveError::OAuth`] on transport failures or redirect loops.
pub async fn follow_oauth_redirect_chain(
    client: &reqwest::Client,
    start_url: &Url,
    max_hops: usize,
) -> Result<OAuthChainResult, DriveError> {
    let mut current = start_url.clone();
    let mut hops = Vec::new();
    let mut cookies = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for _ in 0..max_hops {
        if !seen.insert(current.to_string()) {
            return Err(DriveError::OAuth("redirect loop detected".into()));
        }

        let response = client
            .get(current.clone())
            .send()
            .await
            .map_err(|e| DriveError::OAuth(e.to_string()))?;

        ingest_cookies(response.headers(), &mut cookies);
        let status = response.status().as_u16();

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let next = location
                .as_ref()
                .and_then(|loc| resolve_location(&current, loc))
                .ok_or_else(|| DriveError::OAuth("redirect missing Location".into()))?;

            hops.push(RedirectHop {
                from_url: current.to_string(),
                status,
                location: location.clone(),
            });
            current = next;
            continue;
        }

        return Ok(OAuthChainResult {
            hops,
            final_url: current.to_string(),
            final_status: status,
            cookies,
        });
    }

    Err(DriveError::OAuth(format!(
        "exceeded max redirect hops ({max_hops})"
    )))
}

fn resolve_location(base: &Url, location: &str) -> Option<Url> {
    if let Ok(abs) = Url::parse(location) {
        return Some(abs);
    }
    base.join(location).ok()
}

fn ingest_cookies(headers: &HeaderMap, out: &mut Vec<(String, String)>) {
    for value in headers.get_all("set-cookie") {
        if let Ok(s) = value.to_str() {
            if let Some((name, val)) = parse_set_cookie_pair(s) {
                out.push((name, val));
            }
        }
    }
}

fn parse_set_cookie_pair(header: &str) -> Option<(String, String)> {
    let pair = header.split(';').next()?.trim();
    let (name, value) = pair.split_once('=')?;
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_location() {
        let base = Url::parse("https://app.example/oauth/start").expect("url");
        let next = resolve_location(&base, "/callback?code=abc").expect("join");
        assert_eq!(next.as_str(), "https://app.example/callback?code=abc");
    }

    #[test]
    fn parses_set_cookie_pair() {
        let (name, value) =
            parse_set_cookie_pair("session=abc123; Path=/; HttpOnly").expect("cookie");
        assert_eq!(name, "session");
        assert_eq!(value, "abc123");
    }
}
