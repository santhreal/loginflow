//! Discover HTML login forms: username/password fields, CSRF tokens, honeypot skip.

use crate::error::DiscoverError;
use scraper::{ElementRef, Html, Selector};
use std::collections::HashSet;
use url::Url;

/// HTTP method for a discovered form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMethod {
    /// GET form submission.
    Get,
    /// POST form submission.
    Post,
}

impl FormMethod {
    /// Wire method string for scald-compatible [`crate::ScaldLoginFlow`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// A login form discovered in HTML.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredForm {
    /// Resolved submission URL.
    pub action_url: String,
    /// GET or POST.
    pub method: FormMethod,
    /// `name` attribute of the username/email field.
    pub username_field: String,
    /// `name` attribute of the password field.
    pub password_field: String,
    /// Hidden CSRF fields to replay on submit.
    pub csrf_fields: Vec<(String, String)>,
    /// Other non-honeypot hidden fields to include.
    pub extra_hidden: Vec<(String, String)>,
    /// Optional CSS selector for the submit control.
    pub submit_selector: Option<String>,
    /// CSS selector identifying the form element.
    pub form_selector: String,
    /// Whether a TOTP/MFA code field was detected on this form.
    pub has_totp_field: bool,
    /// Eligible for scald-style HTTP fast-path (no browser/MFA on form).
    pub http_simple: bool,
}

/// Discover all login forms in an HTML document.
///
/// # Errors
///
/// Returns [`DiscoverError::Parse`] when HTML cannot be parsed.
pub fn discover_login_forms_in_html(
    html: &str,
    page_url: &Url,
) -> Result<Vec<DiscoveredForm>, DiscoverError> {
    let document = Html::parse_document(html);
    let form_sel = Selector::parse("form").map_err(|e| DiscoverError::Parse(e.to_string()))?;
    let mut forms = Vec::new();

    for (index, form) in document.select(&form_sel).enumerate() {
        if let Some(discovered) = analyze_form(form, page_url, index) {
            forms.push(discovered);
        }
    }

    Ok(forms)
}

/// Return the highest-scoring login form, if any.
///
/// # Errors
///
/// Propagates parse errors from [`discover_login_forms_in_html`].
pub fn discover_best_login_form(
    html: &str,
    page_url: &Url,
) -> Result<Option<DiscoveredForm>, DiscoverError> {
    let mut forms = discover_login_forms_in_html(html, page_url)?;
    forms.sort_by_key(|b| std::cmp::Reverse(score_form(b)));
    Ok(forms.into_iter().next())
}

fn score_form(form: &DiscoveredForm) -> u32 {
    let mut score = 0u32;
    if form.http_simple {
        score += 10;
    }
    if !form.csrf_fields.is_empty() {
        score += 5;
    }
    if form.submit_selector.is_some() {
        score += 3;
    }
    let lower_action = form.action_url.to_ascii_lowercase();
    for hint in ["/login", "/signin", "/session", "/auth", "/log_in", "/sign_in"] {
        if lower_action.contains(hint) {
            score += 5;
            break;
        }
    }
    score
}

fn analyze_form(form: ElementRef<'_>, page_url: &Url, index: usize) -> Option<DiscoveredForm> {
    let password_sel = Selector::parse("input[type=password]").ok()?;
    let password = form.select(&password_sel).next()?;
    let password_field = field_name(&password)?;

    let username = find_username_field(form)?;
    let username_field = field_name(&username)?;

    if is_search_field(username) {
        return None;
    }

    let method = form
        .value()
        .attr("method")
        .map(|m| {
            if m.eq_ignore_ascii_case("post") {
                FormMethod::Post
            } else {
                FormMethod::Get
            }
        })
        .unwrap_or(FormMethod::Get);

    let action = form.value().attr("action").unwrap_or("");
    let action_url = resolve_action(page_url, action);

    let input_sel = Selector::parse("input, textarea, select").ok()?;
    let mut csrf_fields = Vec::new();
    let mut extra_hidden = Vec::new();
    let mut has_totp_field = false;
    let mut seen_names = HashSet::new();

    for input in form.select(&input_sel) {
        let Some(name) = field_name(&input) else {
            continue;
        };
        if seen_names.contains(&name) {
            continue;
        }
        seen_names.insert(name.clone());

        let input_type = input
            .value()
            .attr("type")
            .unwrap_or("text")
            .to_ascii_lowercase();

        if input_type == "password" {
            continue;
        }

        if is_totp_field(&name, &input_type) {
            has_totp_field = true;
            continue;
        }

        if name == username_field {
            continue;
        }

        if is_honeypot(input) {
            continue;
        }

        let value = input.value().attr("value").unwrap_or("").to_string();
        if is_csrf_name(&name) {
            csrf_fields.push((name, value));
        } else if input_type == "hidden" {
            extra_hidden.push((name, value));
        }
    }

    let form_selector = form_selector_for(form, index);
    let submit_selector = find_submit_selector(form);

    let http_simple = !has_totp_field
        && matches!(method, FormMethod::Get | FormMethod::Post)
        && !action_url.is_empty();

    Some(DiscoveredForm {
        action_url,
        method,
        username_field,
        password_field,
        csrf_fields,
        extra_hidden,
        submit_selector,
        form_selector,
        has_totp_field,
        http_simple,
    })
}

fn find_username_field<'a>(form: ElementRef<'a>) -> Option<ElementRef<'a>> {
    let input_sel = Selector::parse("input, textarea").ok()?;
    let mut best: Option<(u32, ElementRef<'a>)> = None;

    for input in form.select(&input_sel) {
        let input_type = input
            .value()
            .attr("type")
            .unwrap_or("text")
            .to_ascii_lowercase();
        if input_type == "password" || input_type == "submit" || input_type == "button" {
            continue;
        }
        if !matches!(
            input_type.as_str(),
            "text" | "email" | "tel" | "" | "search"
        ) {
            continue;
        }
        let name = field_name(&input).unwrap_or_default();
        let score = username_field_score(&name, input);
        if score == 0 {
            continue;
        }
        match &best {
            None => best = Some((score, input)),
            Some((prev, _)) if score > *prev => best = Some((score, input)),
            _ => {}
        }
    }

    best.map(|(_, el)| el)
}

fn username_field_score(name: &str, input: ElementRef<'_>) -> u32 {
    let lower = name.to_ascii_lowercase();
    let mut score = 0u32;
    for token in ["user", "login", "email", "account", "id"] {
        if lower.contains(token) {
            score += 5;
        }
    }
    if input.value().attr("type") == Some("email") {
        score += 8;
    }
    if let Some(ph) = input.value().attr("placeholder") {
        let ph = ph.to_ascii_lowercase();
        if ph.contains("email") || ph.contains("user") {
            score += 4;
        }
        if ph.contains("search") {
            score = 0;
        }
    }
    if let Some(aria) = input.value().attr("aria-label") {
        let aria = aria.to_ascii_lowercase();
        if aria.contains("search") {
            score = 0;
        }
    }
    score
}

fn is_search_field(input: ElementRef<'_>) -> bool {
    if let Some(ph) = input.value().attr("placeholder") {
        let ph = ph.to_ascii_lowercase();
        if ph.contains("search") {
            return true;
        }
    }
    if let Some(aria) = input.value().attr("aria-label") {
        if aria.to_ascii_lowercase().contains("search") {
            return true;
        }
    }
    false
}

fn is_totp_field(name: &str, input_type: &str) -> bool {
    if is_csrf_name(name) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if input_type == "tel" && (lower.contains("otp") || lower.contains("2fa")) {
        return true;
    }
    ["otp", "totp", "mfa", "2fa", "authenticator"]
        .iter()
        .any(|t| lower.contains(t))
        || (lower.contains("code") && !lower.contains("postal") && !lower.contains("zip"))
}

fn is_csrf_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("csrf")
        || lower == "_token"
        || lower.contains("authenticity")
        || lower.contains("requestverification")
        || lower == "csrfmiddlewaretoken"
}

fn is_honeypot(input: ElementRef<'_>) -> bool {
    let name = field_name(&input).unwrap_or_default().to_ascii_lowercase();
    if name.contains("honeypot") || name == "url" || name.starts_with("hp_") {
        return true;
    }
    if let Some(class) = input.value().attr("class") {
        if class.to_ascii_lowercase().contains("honeypot") {
            return true;
        }
    }
    if input.value().attr("tabindex") == Some("-1") {
        return true;
    }
    if let Some(style) = input.value().attr("style") {
        let s = style.to_ascii_lowercase();
        if s.contains("display:none")
            || s.contains("display: none")
            || s.contains("visibility:hidden")
            || s.contains("left:-")
            || s.contains("opacity:0")
        {
            return true;
        }
    }
    if let Some(aria) = input.value().attr("aria-hidden") {
        if aria == "true" {
            return true;
        }
    }
    false
}

fn field_name(el: &scraper::ElementRef<'_>) -> Option<String> {
    el.value()
        .attr("name")
        .map(str::to_string)
        .or_else(|| el.value().attr("id").map(str::to_string))
}

fn resolve_action(page_url: &Url, action: &str) -> String {
    if action.is_empty() {
        return page_url.to_string();
    }
    match page_url.join(action) {
        Ok(url) => url.to_string(),
        Err(_) => action.to_string(),
    }
}

fn form_selector_for(form: ElementRef<'_>, index: usize) -> String {
    if let Some(id) = form.value().attr("id") {
        return format!("form#{id}");
    }
    if let Some(name) = form.value().attr("name") {
        return format!("form[name=\"{name}\"]");
    }
    format!("form:nth-of-type({})", index + 1)
}

fn find_submit_selector(form: ElementRef<'_>) -> Option<String> {
    let submit_sel = Selector::parse("button[type=submit], input[type=submit]").ok()?;
    let submit = form.select(&submit_sel).next()?;
    if let Some(id) = submit.value().attr("id") {
        return Some(format!("#{id}"));
    }
    if let Some(name) = submit.value().attr("name") {
        return Some(format!("[name=\"{name}\"]"));
    }
    Some("button[type=submit], input[type=submit]".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn discovers_basic_login_form() {
        let html = r#"
        <html><body>
        <form action="/login" method="post">
          <input type="hidden" name="csrf_token" value="abc" />
          <input type="text" name="username" />
          <input type="password" name="password" />
          <button type="submit">Sign in</button>
        </form>
        </body></html>
        "#;
        let page = Url::parse("https://app.example/login").expect("url");
        let form = discover_best_login_form(html, &page)
            .expect("parse")
            .expect("form");
        assert_eq!(form.username_field, "username");
        assert_eq!(form.password_field, "password");
        assert_eq!(form.csrf_fields, vec![("csrf_token".into(), "abc".into())]);
        assert!(form.http_simple);
    }

    #[test]
    fn skips_honeypot_hidden_fields() {
        let html = r#"
        <form action="/login" method="post">
          <input type="hidden" name="hp" style="display:none" value="bot" />
          <input type="text" name="email" />
          <input type="password" name="pass" />
        </form>
        "#;
        let page = Url::parse("https://x.test/").expect("url");
        let form = discover_best_login_form(html, &page)
            .expect("parse")
            .expect("form");
        assert!(form.extra_hidden.iter().all(|(n, _)| n != "hp"));
    }

    #[test]
    fn rejects_search_username_placeholder() {
        let html = r#"
        <form action="/search" method="get">
          <input type="text" name="username" placeholder="Search by username" />
          <input type="password" name="password" />
        </form>
        "#;
        let page = Url::parse("https://x.test/").expect("url");
        let forms = discover_login_forms_in_html(html, &page).expect("parse");
        assert!(forms.is_empty());
    }

    #[test]
    fn missing_method_defaults_to_get_per_html_spec() {
        let html = r#"
        <form action="/login">
          <input type="text" name="user" />
          <input type="password" name="pass" />
        </form>
        "#;
        let page = Url::parse("https://x.test/").expect("url");
        let form = discover_best_login_form(html, &page)
            .expect("parse")
            .expect("form");
        assert_eq!(form.method, FormMethod::Get);
    }

    #[test]
    fn score_form_selects_login_form_over_register_form_with_long_field_name() {
        let html = r#"
        <html><body>
        <form action="/register" method="post">
          <input type="text" name="a_very_long_username_field_name_for_registration" />
          <input type="password" name="register_pass" />
        </form>
        <form action="/login" method="post">
          <input type="hidden" name="csrf_token" value="sec123" />
          <input type="text" name="user" />
          <input type="password" name="pass" />
          <button type="submit">Sign in</button>
        </form>
        </body></html>
        "#;
        let page = Url::parse("https://app.example/home").expect("url");
        let form = discover_best_login_form(html, &page)
            .expect("parse")
            .expect("form");
        assert_eq!(form.action_url, "https://app.example/login");
        assert_eq!(form.username_field, "user");
        assert_eq!(form.csrf_fields, vec![("csrf_token".to_string(), "sec123".to_string())]);
    }

    #[test]
    fn captures_csrf_in_visible_text_field_and_skips_honeypot() {
        let html = r#"
        <form action="/login" method="post">
          <input type="text" name="csrf_token" value="token_val" />
          <input type="text" name="hp_field" style="display:none" value="bot" />
          <input type="text" name="username" />
          <input type="password" name="password" />
        </form>
        "#;
        let page = Url::parse("https://x.test/").expect("url");
        let form = discover_best_login_form(html, &page)
            .expect("parse")
            .expect("form");
        assert_eq!(form.csrf_fields, vec![("csrf_token".to_string(), "token_val".to_string())]);
        assert!(form.extra_hidden.is_empty());
    }
}
