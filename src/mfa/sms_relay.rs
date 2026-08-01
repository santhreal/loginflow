use crate::error::MfaError;
use crate::mfa::{MfaPrompt, MfaResponse, MfaSource};
use async_trait::async_trait;
use reqwest::Url;
use serde::Deserialize;
use std::time::Duration;
use tokio::time::sleep;

/// Source for SMS OTPs by polling a generic SMS receiver API.
#[derive(Debug, Clone)]
pub struct SmsRelayMfaSource {
    api_url: Url,
    phone_number: String,
    poll_interval: Duration,
    max_attempts: usize,
}

#[derive(Debug, Deserialize)]
struct SmsMessage {
    id: String,
    to: String,
    body: String,
}

impl SmsRelayMfaSource {
    /// Create a new source polling a mockable SMS API.
    #[must_use]
    pub fn new(api_url: Url, phone_number: impl Into<String>) -> Self {
        Self {
            api_url,
            phone_number: phone_number.into(),
            poll_interval: Duration::from_secs(2),
            max_attempts: 15,
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
}

#[async_trait]
impl MfaSource for SmsRelayMfaSource {
    async fn fetch(&self, _prompt: &MfaPrompt) -> Result<MfaResponse, MfaError> {
        let client = crate::mfa::polling_client()?;
        for _ in 0..self.max_attempts {
            let mut msgs_url = self.api_url.clone();
            msgs_url.set_path("/messages");

            let resp = match client.get(msgs_url).send().await {
                Ok(r) => r,
                Err(e) => return Err(MfaError::Email(format!("sms network error: {}", e))),
            };

            let messages: Vec<SmsMessage> = match resp.json().await {
                Ok(m) => m,
                Err(e) => return Err(MfaError::Email(format!("sms parse error: {}", e))),
            };

            for msg in messages {
                if msg.to.contains(&self.phone_number) {
                    if let Some(code) = extract_otp_from_sms(&msg.body) {
                        // Delete the message so it isn't processed again.
                        let mut del_url = self.api_url.clone();
                        del_url.set_path(&format!("/messages/{}", msg.id));
                        let _ = client.delete(del_url).send().await;

                        return Ok(MfaResponse { code });
                    }
                }
            }

            sleep(self.poll_interval).await;
        }

        Err(MfaError::Email("polling timed out waiting for sms".into()))
    }
}

/// Extract a 6-digit code from the SMS body.
fn extract_otp_from_sms(body: &str) -> Option<String> {
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

    None
}
