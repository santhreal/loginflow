//! OAuth / SSO entry-point discovery.

use loginflow::discover_oauth_entry_points;
use url::Url;

const MIXED_PAGE: &str = r#"
<html><body>
  <a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=app">Sign in with Google</a>
  <a href="https://github.com/login/oauth/authorize?client_id=app">Continue with GitHub</a>
  <a href="/privacy">Privacy policy</a>
</body></html>
"#;

#[test]
fn discovers_google_and_github_providers() {
    let page = Url::parse("https://app.example/signin").expect("url");
    let entries = discover_oauth_entry_points(MIXED_PAGE, &page).expect("parse");
    assert!(entries.len() >= 2);
    let ids: Vec<_> = entries.iter().map(|e| e.provider_id.as_str()).collect();
    assert!(ids.contains(&"google"));
    assert!(ids.contains(&"github"));
}
