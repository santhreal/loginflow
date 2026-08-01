use crate::error::MfaError;
use crate::mfa::{MfaPrompt, MfaResponse, MfaSource};
use async_trait::async_trait;
use reqwest::Url;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;

/// Source for Email Magic Links or OTPs by polling a Mailcatcher-like HTTP API.
#[derive(Debug, Clone)]
pub struct EmailLinkMfaSource {
    api_url: Url,
    recipient: String,
    poll_interval: Duration,
    max_attempts: usize,
    /// Hosts that a magic link is allowed to point to (e.g. `example.com`).
    /// If empty, all `https://` hosts are considered, but `http://` is always rejected.
    allowed_hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MailMessage {
    id: u64,
    recipients: Vec<String>,
}

impl EmailLinkMfaSource {
    /// Create a new source polling a Mailcatcher-like API.
    #[must_use]
    pub fn new(api_url: Url, recipient: impl Into<String>) -> Self {
        Self {
            api_url,
            recipient: recipient.into(),
            poll_interval: Duration::from_secs(2),
            max_attempts: 15,
            allowed_hosts: Vec::new(),
        }
    }

    /// Set the polling interval.
    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Set the maximum number of attempts.
    #[must_use]
    pub fn with_max_attempts(mut self, attempts: usize) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Restrict extracted magic links to the given host names (case-insensitive).
    /// Repeat calls append to the list. `http://` links are always rejected.
    #[must_use]
    pub fn with_allowed_host(mut self, host: impl Into<String>) -> Self {
        self.allowed_hosts.push(host.into());
        self
    }

    /// Replace the full list of allowed magic-link hosts.
    #[must_use]
    pub fn with_allowed_hosts(
        mut self,
        hosts: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allowed_hosts = hosts.into_iter().map(Into::into).collect();
        self
    }
}

#[async_trait]
impl MfaSource for EmailLinkMfaSource {
    async fn fetch(&self, _prompt: &MfaPrompt) -> Result<MfaResponse, MfaError> {
        let client = crate::mfa::polling_client()?;
        for _ in 0..self.max_attempts {
            let mut msgs_url = self.api_url.clone();
            msgs_url.set_path("/messages");

            let resp = match client.get(msgs_url).send().await {
                Ok(r) => r,
                Err(e) => return Err(MfaError::Email(format!("network error: {}", e))),
            };

            let messages: Vec<MailMessage> = match resp.json().await {
                Ok(m) => m,
                Err(e) => return Err(MfaError::Email(format!("parse error: {}", e))),
            };

            for msg in messages {
                if msg.recipients.iter().any(|r| r.contains(&self.recipient)) {
                    let mut body_url = self.api_url.clone();
                    body_url.set_path(&format!("/messages/{}.plain", msg.id));

                    let body_resp = match client.get(body_url).send().await {
                        Ok(r) => r,
                        Err(e) => return Err(MfaError::Email(format!("network error: {}", e))),
                    };

                    let body = match body_resp.text().await {
                        Ok(b) => b,
                        Err(e) => return Err(MfaError::Email(format!("body parse error: {}", e))),
                    };

                    if let Some(code) = extract_otp_or_link(&body, &self.allowed_hosts) {
                        // Delete the message so we don't read it again on subsequent fetch calls.
                        let mut del_url = self.api_url.clone();
                        del_url.set_path(&format!("/messages/{}", msg.id));
                        let _ = client.delete(del_url).send().await;

                        return Ok(MfaResponse { code });
                    }
                }
            }

            sleep(self.poll_interval).await;
        }

        Err(MfaError::Email(
            "polling timed out waiting for email".into(),
        ))
    }
}

/// Substrings that suggest a URL is a magic/authentication link, not an unrelated
/// footer or decoy.
const MAGIC_LINK_HINTS: &[&str] = &[
    "token",
    "magic",
    "login",
    "auth",
    "verify",
    "confirm",
    "otp",
    "mfa",
    "signin",
    "authorize",
];

/// Extract a 6-digit OTP or a magic link from the text.
///
/// Magic-link extraction is hardened against attacker-influenced bodies:
/// - `http://` links are rejected to prevent downgrade attacks.
/// - `https://` links whose host is not in `allowed_hosts` (if configured) are skipped.
/// - When multiple candidates exist, the URL whose path/query most strongly hints at
///   a login/magic-link is chosen, so a decoy URL placed earlier in the body is not
///   blindly followed.
fn extract_otp_or_link(body: &str, allowed_hosts: &[String]) -> Option<String> {
    // Try to find a 6-digit code
    let mut current_digits = String::new();
    for c in body.chars() {
        if c.is_ascii_digit() {
            current_digits.push(c);
        } else {
            if current_digits.len() == 6 {
                return Some(current_digits);
            }
            current_digits.clear();
        }
    }
    if current_digits.len() == 6 {
        return Some(current_digits);
    }

    // Try to find a magic link.
    let mut best_candidate: Option<(String, usize)> = None;
    for scheme in ["https://"] {
        for (start, _) in body.match_indices(scheme) {
            let slice = &body[start..];
            let raw = if let Some(end) = slice.find(|c: char| {
                c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>' || c == ')'
            }) {
                &slice[..end]
            } else {
                slice
            };
            if let Ok(url) = Url::parse(raw) {
                if url.scheme() != "https" {
                    continue;
                }
                let host = url.host_str().unwrap_or("").to_lowercase();
                if !allowed_hosts.is_empty()
                    && !allowed_hosts.iter().any(|h| host == h.to_lowercase())
                {
                    continue;
                }
                let path_and_query =
                    format!("{}{}", url.path(), url.query().unwrap_or("")).to_lowercase();
                let score = MAGIC_LINK_HINTS
                    .iter()
                    .map(|hint| path_and_query.matches(hint).count() * hint.len())
                    .sum();
                if best_candidate.as_ref().map_or(true, |(_, s)| score > *s) {
                    best_candidate = Some((raw.to_string(), score));
                }
            }
        }
    }

    best_candidate.map(|(url, _)| url)
}
