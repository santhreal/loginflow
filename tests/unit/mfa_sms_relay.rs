use loginflow::mfa::sms_relay::SmsRelayMfaSource;
use loginflow::mfa::{MfaPrompt, MfaSource};
use reqwest::Url;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_sms_relay_happy_path() {
    let mock_server = MockServer::start().await;

    // First request: empty messages
    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Second request: valid SMS message
    let valid_message = serde_json::json!([{
        "id": "msg_123",
        "to": "+15551234567",
        "body": "Your verification code is 123456. Do not share it."
    }]);

    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(valid_message))
        .mount(&mock_server)
        .await;

    // Mock DELETE request
    Mock::given(method("DELETE"))
        .and(path("/messages/msg_123"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let api_url = Url::parse(&mock_server.uri()).expect("Fix: Valid URL");
    let source = SmsRelayMfaSource::new(api_url, "+15551234567")
        .with_poll_interval(Duration::from_millis(10))
        .with_max_attempts(5);

    let prompt = MfaPrompt::Totp { field_name: None };
    let result = source
        .fetch(&prompt)
        .await
        .expect("Fix: fetch should succeed");

    assert_eq!(
        result.code, "123456",
        "Fix: must extract the correct 6-digit code"
    );
}
