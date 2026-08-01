//! Shared HTTP identity wiring for loginflow's reqwest clients.

use reqwest::header::HeaderMap;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) enum HttpIdentity {
    #[default]
    None,
    #[cfg(feature = "stealth")]
    Stealth(guise::ProfileBundle),
}

pub(crate) fn apply_to_client_builder(
    builder: reqwest::ClientBuilder,
    identity: HttpIdentity,
) -> Result<reqwest::ClientBuilder, String> {
    match identity {
        HttpIdentity::None => Ok(builder),
        #[cfg(feature = "stealth")]
        HttpIdentity::Stealth(bundle) => Ok(builder.default_headers(header_map(bundle)?)),
    }
}

pub(crate) fn apply_to_header_map(
    headers: &mut HeaderMap,
    identity: HttpIdentity,
) -> Result<(), String> {
    match identity {
        HttpIdentity::None => {
            let _ = headers;
            Ok(())
        }
        #[cfg(feature = "stealth")]
        HttpIdentity::Stealth(bundle) => {
            guise::http::apply_browser_header_map_without_compression(headers, bundle.browser)
                .map_err(header_error)
        }
    }
}

#[cfg(feature = "stealth")]
fn header_map(bundle: guise::ProfileBundle) -> Result<HeaderMap, String> {
    guise::http::browser_header_map_without_compression(bundle.browser).map_err(header_error)
}

#[cfg(feature = "stealth")]
fn header_error(error: guise::http::BrowserHeaderMapError) -> String {
    format!(
        "invalid stealth HTTP headers for loginflow: {error}. Fix: repair the shared stealth profile header catalog or choose a valid ProfileBundle."
    )
}

#[cfg(all(test, feature = "stealth"))]
mod tests {
    use super::*;
    use guise::{ProfileBundle, StealthProfile};
    use reqwest::header::{HeaderValue, ACCEPT, ACCEPT_LANGUAGE};

    #[test]
    fn stealth_identity_applies_shared_headers_without_overriding_callers() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        apply_to_header_map(
            &mut headers,
            HttpIdentity::Stealth(ProfileBundle::for_browser(StealthProfile::FirefoxWindows)),
        )
        .expect("headers should build");

        let facts = guise::fingerprint::profile_facts(StealthProfile::FirefoxWindows);
        assert_eq!(
            headers.get("User-Agent").and_then(|v| v.to_str().ok()),
            Some(facts.user_agent)
        );
        assert_eq!(
            headers.get(ACCEPT).and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            headers.get(ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()),
            Some(facts.accept_language)
        );
        assert!(
            !headers.contains_key("Accept-Encoding"),
            "loginflow reqwest clients do not own explicit decompression negotiation"
        );
    }
}
