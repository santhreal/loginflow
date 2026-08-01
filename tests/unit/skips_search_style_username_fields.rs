//! HTML login form discovery fixtures.

use loginflow::discover_login_forms_in_html;
use url::Url;

const SIMPLE_LOGIN: &str = r#"
<!DOCTYPE html>
<html>
<body>
  <form id="login" action="/api/login" method="post">
    <input type="hidden" name="csrfmiddlewaretoken" value="tok123" />
    <input type="text" name="username" autocomplete="username" />
    <input type="password" name="password" autocomplete="current-password" />
    <input type="hidden" name="trap" style="display:none;position:absolute;left:-9999px" value="" />
    <button type="submit">Log in</button>
  </form>
</body>
</html>
"#;

const SEARCH_TRAP: &str = r#"
<form method="get" action="/search">
  <input type="text" name="username" placeholder="Search by username" />
  <input type="password" name="password" />
</form>
"#;

const MFA_FORM: &str = r#"
<form action="/login" method="post">
  <input name="email" type="email" />
  <input name="password" type="password" />
  <input name="totp_code" type="text" />
</form>
"#;

#[test]
fn skips_search_style_username_fields() {
    let base = Url::parse("https://app.example.com/").expect("url");
    let forms = discover_login_forms_in_html(SEARCH_TRAP, &base).expect("parse");
    assert!(forms.is_empty());
}
