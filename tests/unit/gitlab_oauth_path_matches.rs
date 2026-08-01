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
fn gitlab_oauth_path_matches() {
    let html = r#"<a href="https://gitlab.com/oauth/authorize">GitLab</a>"#;
    let page = Url::parse("https://app.example/").expect("url");
    let entries = discover_oauth_entry_points(html, &page).expect("parse");
    assert_eq!(entries[0].provider_id, "gitlab");
}
