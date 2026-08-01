use loginflow::error::MfaError;
use loginflow::mfa::sms_relay::SmsRelayMfaSource;
use loginflow::mfa::{MfaPrompt, MfaSource};
use reqwest::Url;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_sms_relay_timeout() {
    let mock_server = MockServer::start().await;

    // Server always returns empty array
    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
        .mount(&mock_server)
        .await;

    let api_url = Url::parse(&mock_server.uri()).expect("Fix: Valid URL");
    let source = SmsRelayMfaSource::new(api_url, "+15551234567")
        .with_poll_interval(Duration::from_millis(10))
        .with_max_attempts(3);

    let prompt = MfaPrompt::Totp { field_name: None };
    let result = source.fetch(&prompt).await;

    assert!(result.is_err(), "Fix: Expected timeout error");
    if let Err(MfaError::Email(msg)) = result {
        assert!(
            msg.contains("polling timed out"),
            "Fix: Unexpected error message: {}",
            msg
        );
    } else {
        panic!("Fix: Expected MfaError::Email, got {:?}", result);
    }
}

#[tokio::test]
async fn test_sms_relay_malformed_json() {
    let mock_server = MockServer::start().await;

    // Server returns malformed JSON
    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&mock_server)
        .await;

    let api_url = Url::parse(&mock_server.uri()).expect("Fix: Valid URL");
    let source = SmsRelayMfaSource::new(api_url, "+15551234567")
        .with_poll_interval(Duration::from_millis(10))
        .with_max_attempts(1);

    let prompt = MfaPrompt::Totp { field_name: None };
    let result = source.fetch(&prompt).await;

    assert!(result.is_err(), "Fix: Expected parse error");
    if let Err(MfaError::Email(msg)) = result {
        assert!(
            msg.contains("sms parse error"),
            "Fix: Unexpected error message: {}",
            msg
        );
    } else {
        panic!("Fix: Expected MfaError::Email, got {:?}", result);
    }
}

#[tokio::test]
async fn test_sms_relay_network_error() {
    // Generate a URL that will refuse connection
    let api_url = Url::parse("http://127.0.0.1:0").expect("Fix: Valid URL");

    let source = SmsRelayMfaSource::new(api_url, "+15551234567")
        .with_poll_interval(Duration::from_millis(10))
        .with_max_attempts(1);

    let prompt = MfaPrompt::Totp { field_name: None };
    let result = source.fetch(&prompt).await;

    assert!(result.is_err(), "Fix: Expected network error");
    if let Err(MfaError::Email(msg)) = result {
        assert!(
            msg.contains("sms network error"),
            "Fix: Unexpected error message: {}",
            msg
        );
    } else {
        panic!("Fix: Expected MfaError::Email, got {:?}", result);
    }
}
