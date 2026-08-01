use loginflow::mfa::email_link::EmailLinkMfaSource;
use loginflow::mfa::{MfaPrompt, MfaSource};
use std::time::Duration;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_email_link_extracts_code() {
    let mock_server = MockServer::start().await;

    // Mock GET /messages
    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 1,
                "recipients": ["wrong@example.com"]
            },
            {
                "id": 2,
                "recipients": ["target@example.com"]
            }
        ])))
        .mount(&mock_server)
        .await;

    // Mock GET /messages/2.plain
    Mock::given(method("GET"))
        .and(path("/messages/2.plain"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Your login code is 123456."))
        .mount(&mock_server)
        .await;

    // Mock DELETE /messages/2
    Mock::given(method("DELETE"))
        .and(path("/messages/2"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let api_url = Url::parse(&mock_server.uri()).expect("Fix: mock server uri must parse");
    let source = EmailLinkMfaSource::new(api_url, "target@example.com")
        .with_max_attempts(1)
        .with_poll_interval(Duration::from_millis(10))
        .with_allowed_host("magic.link");

    let resp = source
        .fetch(&MfaPrompt::Totp { field_name: None })
        .await
        .expect("Fix: fetch must succeed");

    assert_eq!(
        resp.code, "123456",
        "Fix: must extract the correct 6-digit code"
    );
}

#[tokio::test]
async fn test_email_link_extracts_url() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 42,
                "recipients": ["target@example.com"]
            }
        ])))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/messages/42.plain"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Click here: https://magic.link/login?token=abc"),
        )
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/messages/42"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let api_url = Url::parse(&mock_server.uri()).expect("Fix: mock server uri must parse");
    let source = EmailLinkMfaSource::new(api_url, "target@example.com")
        .with_max_attempts(1)
        .with_poll_interval(Duration::from_millis(10))
        .with_allowed_host("magic.link");

    let resp = source
        .fetch(&MfaPrompt::Totp { field_name: None })
        .await
        .expect("Fix: fetch must succeed");

    assert_eq!(
        resp.code, "https://magic.link/login?token=abc",
        "Fix: must extract the magic link URL"
    );
}

#[tokio::test]
async fn test_email_link_prefers_allowed_host_over_decoy() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 7,
                "recipients": ["target@example.com"]
            }
        ])))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/messages/7.plain"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "Phishing: https://evil.com/login?token=decoy\nUse: https://magic.link/login?token=abc",
        ))
        .mount(&mock_server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/messages/7"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let api_url = Url::parse(&mock_server.uri()).expect("Fix: mock server uri must parse");
    let source = EmailLinkMfaSource::new(api_url, "target@example.com")
        .with_max_attempts(1)
        .with_poll_interval(Duration::from_millis(10))
        .with_allowed_host("magic.link");

    let resp = source
        .fetch(&MfaPrompt::Totp { field_name: None })
        .await
        .expect("Fix: fetch must succeed");

    assert_eq!(
        resp.code, "https://magic.link/login?token=abc",
        "Fix: must ignore cross-origin decoy and extract allowed magic link"
    );
}

#[tokio::test]
async fn test_email_link_rejects_http_downgrade() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 8,
                "recipients": ["target@example.com"]
            }
        ])))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/messages/8.plain"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Click here: http://magic.link/login?token=abc"),
        )
        .mount(&mock_server)
        .await;

    let api_url = Url::parse(&mock_server.uri()).expect("Fix: mock server uri must parse");
    let source = EmailLinkMfaSource::new(api_url, "target@example.com")
        .with_max_attempts(1)
        .with_poll_interval(Duration::from_millis(10))
        .with_allowed_host("magic.link");

    let result = source.fetch(&MfaPrompt::Totp { field_name: None }).await;

    assert!(result.is_err(), "Fix: must reject http:// magic link");
}
