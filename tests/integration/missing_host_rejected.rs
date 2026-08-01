use loginflow::{Credentials, LoginFlowBuilder, LoginFlowError};
use secrecy::SecretString;
use url::Url;

#[tokio::test]
async fn missing_host_url_rejected_before_fetch() {
    let flow = LoginFlowBuilder::default().build().expect("build default");
    let creds = Credentials {
        username: "user".to_string(),
        password: SecretString::from("pass"),
        mfa_source: None,
    };
    // A file: URL has no host; the login flow must reject it before fetching.
    let url = Url::parse("file:///etc/passwd").expect("valid url");
    let err = flow
        .login(&url, &creds)
        .await
        .expect_err("missing host must error");
    assert!(
        matches!(err, LoginFlowError::MissingHost),
        "expected MissingHost, got {err:?}"
    );
}
