//! OAuth / SSO entry-point discovery.

use loginflow::discover_best_oauth_entry;
use url::Url;

const MIXED_PAGE: &str = r#"
<html><body>
  <a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=app">Sign in with Google</a>
  <a href="https://github.com/login/oauth/authorize?client_id=app">Continue with GitHub</a>
  <a href="/privacy">Privacy policy</a>
</body></html>
"#;

#[test]
fn best_entry_is_deterministic() {
    let page = Url::parse("https://app.example/").expect("url");
    let a = discover_best_oauth_entry(MIXED_PAGE, &page).expect("parse");
    let b = discover_best_oauth_entry(MIXED_PAGE, &page).expect("parse");
    assert_eq!(a, b);
}
