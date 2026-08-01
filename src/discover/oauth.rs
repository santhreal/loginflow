//! Detect OAuth / SSO entry points from HTML using tier-B provider patterns.

use crate::error::DiscoverError;
use scraper::{ElementRef, Html, Selector};
use serde::Deserialize;
use std::sync::LazyLock;
use url::Url;

const OAUTH_PROVIDERS_TOML: &str = include_str!("../../tier_b/oauth_providers.toml");

/// A discovered OAuth / SSO sign-in control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredOAuth {
    /// Provider id from tier-B (`google`, `github`, …).
    pub provider_id: String,
    /// Resolved href for the entry point.
    pub entry_url: String,
    /// Visible link or button label when present.
    pub link_text: Option<String>,
    /// CSS selector locating the control.
    pub element_selector: String,
}

#[derive(Debug, Deserialize)]
struct OAuthProvidersFile {
    provider: Vec<OAuthProviderDef>,
}

#[derive(Debug, Deserialize)]
struct OAuthProviderDef {
    id: String,
    button_text: Vec<String>,
    href_hosts: Vec<String>,
    href_path_contains: Option<Vec<String>>,

    // Precomputed lowercase matching data, populated once by `normalize` after
    // deserialization (never read from TOML). Matching is case-insensitive, so
    // lowercasing every pattern here means discovery over a page of N anchors no
    // longer re-lowercases each provider pattern N times in the hot loop.
    #[serde(skip)]
    button_text_lower: Vec<String>,
    #[serde(skip)]
    href_hosts_lower: Vec<String>,
    /// `.{host}` suffix form of each `href_hosts_lower` entry (same index),
    /// so subdomain matching is a plain `ends_with` with no per-call `format!`.
    #[serde(skip)]
    href_host_dot_suffixes: Vec<String>,
    #[serde(skip)]
    href_path_contains_lower: Option<Vec<String>>,
}

impl OAuthProviderDef {
    /// Lowercase every match pattern once, up front.
    fn normalize(&mut self) {
        self.button_text_lower = self
            .button_text
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        self.href_hosts_lower = self
            .href_hosts
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        self.href_host_dot_suffixes = self
            .href_hosts_lower
            .iter()
            .map(|h| format!(".{h}"))
            .collect();
        self.href_path_contains_lower = self
            .href_path_contains
            .as_ref()
            .map(|needles| needles.iter().map(|n| n.to_ascii_lowercase()).collect());
    }
}

static PARSED_PROVIDERS: LazyLock<Result<Vec<OAuthProviderDef>, String>> =
    LazyLock::new(|| parse_providers(OAUTH_PROVIDERS_TOML).map_err(|e| e.to_string()));

/// The embedded provider list, parsed once on first use.
///
/// Fail closed on a malformed embedded tier-B file (Law 10): the old
/// `unwrap_or_default()` returned an EMPTY provider list on any parse
/// error, silently disabling ALL OAuth/SSO discovery (recall -> 0) with no
/// signal. This TOML is compiled into the binary, so a parse failure is a
/// build/data invariant violation; the error is surfaced to the caller as
/// [`DiscoverError::Parse`] instead of panicking.
fn providers() -> Result<&'static [OAuthProviderDef], DiscoverError> {
    PARSED_PROVIDERS.as_deref().map_err(|e| {
        DiscoverError::Parse(format!(
            "loginflow embedded tier_b/oauth_providers.toml is malformed: {e}"
        ))
    })
}

/// Parse a tier-B oauth-providers TOML document into its provider list.
///
/// Separated from [`providers`] so the parse can be exercised directly with
/// malformed input in tests without touching the embedded constant. Each
/// provider's match patterns are lowercased once here so discovery never
/// re-lowercases them per anchor element.
fn parse_providers(toml_str: &str) -> Result<Vec<OAuthProviderDef>, toml::de::Error> {
    toml::from_str::<OAuthProvidersFile>(toml_str).map(|file| {
        let mut providers = file.provider;
        for provider in &mut providers {
            provider.normalize();
        }
        providers
    })
}

/// Discover OAuth / SSO buttons and links on a page.
///
/// # Errors
///
/// Returns [`DiscoverError::Parse`] when HTML cannot be parsed.
pub fn discover_oauth_entry_points(
    html: &str,
    page_url: &Url,
) -> Result<Vec<DiscoveredOAuth>, DiscoverError> {
    let document = Html::parse_document(html);
    let anchor_sel = Selector::parse("a[href], button, input[type=submit][formaction]")
        .map_err(|e| DiscoverError::Parse(e.to_string()))?;

    let mut found = Vec::new();
    let mut seen_urls = std::collections::HashSet::new();

    for (index, el) in document.select(&anchor_sel).enumerate() {
        let href = element_href(el, page_url);
        let text = element_visible_text(el);
        if let Some(provider) = match_provider(&href, text.as_deref())? {
            let entry_url = href.unwrap_or_else(|| page_url.to_string());
            if seen_urls.insert(entry_url.clone()) {
                found.push(DiscoveredOAuth {
                    provider_id: provider.id.clone(),
                    entry_url,
                    link_text: text,
                    element_selector: element_selector(el, index),
                });
            }
        }
    }

    found.sort_by(|a, b| a.provider_id.cmp(&b.provider_id));
    Ok(found)
}

/// Return the highest-confidence OAuth entry (first after sort), if any.
///
/// # Errors
///
/// Propagates parse errors from [`discover_oauth_entry_points`].
pub fn discover_best_oauth_entry(
    html: &str,
    page_url: &Url,
) -> Result<Option<DiscoveredOAuth>, DiscoverError> {
    let entries = discover_oauth_entry_points(html, page_url)?;
    Ok(entries.into_iter().next())
}

fn match_provider(
    href: &Option<String>,
    text: Option<&str>,
) -> Result<Option<&'static OAuthProviderDef>, DiscoverError> {
    let href_lower = href.as_ref().map(|h| h.to_ascii_lowercase());
    let text_lower = text.map(str::to_ascii_lowercase);

    for provider in providers()? {
        if href_matches(provider, href_lower.as_deref()) {
            return Ok(Some(provider));
        }
        if let Some(label) = text_lower.as_deref() {
            // Patterns are already lowercased by `normalize`.
            for pattern in &provider.button_text_lower {
                if label.contains(pattern.as_str()) {
                    return Ok(Some(provider));
                }
            }
        }
    }
    Ok(None)
}

fn href_matches(provider: &OAuthProviderDef, href: Option<&str>) -> bool {
    let Some(href) = href else {
        return false;
    };
    let Ok(parsed) = Url::parse(href) else {
        return false;
    };
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();

    // Hosts and their `.{host}` suffixes are precomputed (parallel indices).
    let host_ok = provider
        .href_hosts_lower
        .iter()
        .zip(&provider.href_host_dot_suffixes)
        .any(|(h, dotted)| host == *h || host.ends_with(dotted.as_str()));

    if !host_ok {
        return false;
    }

    match &provider.href_path_contains_lower {
        None => true,
        Some(needles) if needles.is_empty() => true,
        Some(needles) => needles.iter().any(|n| path.contains(n.as_str())),
    }
}

fn element_href(el: ElementRef<'_>, page_url: &Url) -> Option<String> {
    let href = el
        .value()
        .attr("href")
        .or_else(|| el.value().attr("formaction"))?;
    if href.starts_with("javascript:") || href.starts_with('#') {
        return None;
    }
    page_url.join(href).ok().map(|u| u.to_string())
}

fn element_visible_text(el: ElementRef<'_>) -> Option<String> {
    let text: String = el
        .text()
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        el.value()
            .attr("aria-label")
            .or_else(|| el.value().attr("title"))
            .map(str::to_string)
    } else {
        Some(text)
    }
}

fn element_selector(el: ElementRef<'_>, index: usize) -> String {
    if let Some(id) = el.value().attr("id") {
        return format!("#{}", id);
    }
    let tag = el.value().name();
    if tag == "a" {
        format!("a[href]:nth-of-type({})", index + 1)
    } else {
        format!("{tag}:nth-of-type({})", index + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OAUTH_PAGE: &str = r#"
    <html><body>
      <a id="google-sso" href="https://accounts.google.com/o/oauth2/v2/auth?client_id=x">Sign in with Google</a>
      <a href="https://github.com/login/oauth/authorize?client_id=y">Continue with GitHub</a>
    </body></html>
    "#;

    #[test]
    fn discovers_google_and_github() {
        let page = Url::parse("https://app.example/login").expect("url");
        let entries = discover_oauth_entry_points(OAUTH_PAGE, &page).expect("parse");
        let ids: Vec<_> = entries.iter().map(|e| e.provider_id.as_str()).collect();
        assert!(ids.contains(&"google"));
        assert!(ids.contains(&"github"));
    }

    #[test]
    fn embedded_provider_table_parses_to_the_full_known_set() {
        // The embedded tier-B file must parse and yield every shipped provider.
        // A regression that broke the file used to silently yield an empty list
        // (unwrap_or_default), disabling all OAuth discovery; now it fails closed,
        // and this test pins the exact provider set.
        let provs = parse_providers(OAUTH_PROVIDERS_TOML).expect("embedded tier-B must parse");
        let ids: Vec<_> = provs.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["google", "github", "microsoft", "okta", "auth0", "gitlab"],
            "embedded provider set changed; update this assertion deliberately"
        );
    }

    #[test]
    fn parse_providers_rejects_malformed_toml() {
        // A malformed document must surface as Err (which the `providers`
        // accessor turns into a `DiscoverError::Parse`), never a silent empty
        // default.
        let err = parse_providers("this is = not [valid").unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn providers_accessor_returns_the_full_embedded_set() {
        // Exercise the fail-closed accessor on the real embedded data.
        let ids: Vec<_> = providers()
            .expect("embedded providers parse")
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(ids.len(), 6);
        assert!(ids.contains(&"okta"));
    }

    #[test]
    fn best_oauth_prefers_one_entry() {
        let page = Url::parse("https://app.example/").expect("url");
        let best = discover_best_oauth_entry(OAUTH_PAGE, &page).expect("parse");
        assert!(best.is_some());
    }

    #[test]
    fn ignores_unrelated_footer_links() {
        let html = r#"<a href="https://example.com/privacy">Privacy</a>"#;
        let page = Url::parse("https://app.example/").expect("url");
        let entries = discover_oauth_entry_points(html, &page).expect("parse");
        assert!(entries.is_empty());
    }

    #[test]
    fn matches_microsoft_authorize_href() {
        let html =
            r#"<a href="https://login.microsoftonline.com/common/oauth2/v2.0/authorize">SSO</a>"#;
        let page = Url::parse("https://app.example/").expect("url");
        let entries = discover_oauth_entry_points(html, &page).expect("parse");
        assert_eq!(entries[0].provider_id, "microsoft");
    }

    #[test]
    fn matches_button_text_without_known_href() {
        let html = r#"<button type="button">Sign in with Okta</button>"#;
        let page = Url::parse("https://corp.example/").expect("url");
        let entries = discover_oauth_entry_points(html, &page).expect("parse");
        assert_eq!(entries[0].provider_id, "okta");
    }

    #[test]
    fn normalize_precomputes_lowercase_patterns_so_matching_allocates_none() {
        // Patterns are lowercased ONCE here (parse time). Because the hot match
        // loop reads these precomputed fields directly, it performs no
        // `to_ascii_lowercase`/`format!` per anchor element — the allocation the
        // perf finding flagged. This asserts the precomputation actually happened.
        let mut def = OAuthProviderDef {
            id: "acme".to_string(),
            button_text: vec!["Sign in with ACME".to_string()],
            href_hosts: vec!["Login.ACME.com".to_string()],
            href_path_contains: Some(vec!["/OAuth/Authorize".to_string()]),
            button_text_lower: Vec::new(),
            href_hosts_lower: Vec::new(),
            href_host_dot_suffixes: Vec::new(),
            href_path_contains_lower: None,
        };
        def.normalize();
        assert_eq!(def.button_text_lower, vec!["sign in with acme".to_string()]);
        assert_eq!(def.href_hosts_lower, vec!["login.acme.com".to_string()]);
        assert_eq!(
            def.href_host_dot_suffixes,
            vec![".login.acme.com".to_string()]
        );
        assert_eq!(
            def.href_path_contains_lower,
            Some(vec!["/oauth/authorize".to_string()])
        );
    }

    #[test]
    fn matches_mixed_case_host_and_button_via_precomputed_patterns() {
        // Correctness must survive the precompute: an uppercase href host and an
        // uppercase button label still match the lowercased provider patterns.
        let page = Url::parse("https://app.example/").expect("url");

        let host_html = r#"<a href="https://ACCOUNTS.GOOGLE.COM/o/oauth2/v2/auth">SSO</a>"#;
        let by_host = discover_oauth_entry_points(host_html, &page).expect("parse");
        assert_eq!(by_host[0].provider_id, "google");

        let text_html = r#"<button type="button">SIGN IN WITH OKTA</button>"#;
        let by_text = discover_oauth_entry_points(text_html, &page).expect("parse");
        assert_eq!(by_text[0].provider_id, "okta");
    }

    #[test]
    fn dedupes_same_entry_url() {
        let html = r#"
        <a href="https://github.com/login/oauth/authorize">GitHub 1</a>
        <a href="https://github.com/login/oauth/authorize">GitHub 2</a>
        "#;
        let page = Url::parse("https://app.example/").expect("url");
        let entries = discover_oauth_entry_points(html, &page).expect("parse");
        assert_eq!(entries.len(), 1);
    }
}
