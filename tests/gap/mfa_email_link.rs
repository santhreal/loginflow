use loginflow::error::MfaError;
use loginflow::mfa::email_link::EmailLinkMfaSource;
use loginflow::mfa::{MfaPrompt, MfaSource};
use std::time::Duration;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_email_link_timeout_exhaustion() {
    let mock_server = MockServer::start().await;

    // Return empty message list to simulate no matching emails arriving
    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&mock_server)
        .await;

    let api_url = Url::parse(&mock_server.uri()).expect("Fix: mock server uri must parse");

    // Configure to fail fast
    let source = EmailLinkMfaSource::new(api_url, "target@example.com")
        .with_max_attempts(2)
        .with_poll_interval(Duration::from_millis(5));

    let result = source.fetch(&MfaPrompt::Totp { field_name: None }).await;

    match result {
        Err(MfaError::Email(msg)) => {
            assert!(
                msg.contains("polling timed out"),
                "Fix: expected timeout message, got: {}",
                msg
            );
        }
        other => panic!("Fix: expected Email timeout error, got {:?}", other),
    }
}
