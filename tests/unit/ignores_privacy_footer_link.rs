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
fn ignores_privacy_footer_link() {
    let page = Url::parse("https://app.example/").expect("url");
    let entries = discover_oauth_entry_points(MIXED_PAGE, &page).expect("parse");
    assert!(entries.iter().all(|e| !e.entry_url.contains("privacy")));
}
