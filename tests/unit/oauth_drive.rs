//! OAuth redirect chain drive (wiremock).

use loginflow::{follow_oauth_redirect_chain, oauth_redirect_client, OAuthChainResult};
use std::time::Duration;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn follows_three_hop_chain() {
    let server = MockServer::start().await;
    let start = format!("{}/oauth/start", server.uri());

    Mock::given(method("GET"))
        .and(path("/oauth/start"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/oauth/idp", server.uri())),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/oauth/idp"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            format!("{}/oauth/callback?code=abc", server.uri()),
        ))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/oauth/callback"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "session=oauth-done; Path=/; HttpOnly"),
        )
        .mount(&server)
        .await;

    let client = oauth_redirect_client(Duration::from_secs(5)).expect("client");
    let start_url = Url::parse(&start).expect("url");
    let result = follow_oauth_redirect_chain(&client, &start_url, 8)
        .await
        .expect("chain");

    assert_eq!(result.hops.len(), 2);
    assert!(result.final_url.contains("/oauth/callback"));
    assert_eq!(result.final_status, 200);
    assert!(result
        .cookies
        .iter()
        .any(|(n, v)| n == "session" && v == "oauth-done"));
}

#[tokio::test]
async fn single_redirect_to_terminal() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/login"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", format!("{}/done", server.uri())),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/done"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let client = oauth_redirect_client(Duration::from_secs(5)).expect("client");
    let url = Url::parse(&format!("{}/login", server.uri())).expect("url");
    let result = follow_oauth_redirect_chain(&client, &url, 5)
        .await
        .expect("chain");
    assert_eq!(result.hops.len(), 1);
    assert_eq!(result.final_status, 204);
}

#[tokio::test]
async fn accumulates_cookies_from_intermediate_hops() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/a"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Set-Cookie", "hop1=a; Path=/")
                .insert_header("Location", format!("{}/b", server.uri())),
        )
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/b"))
        .respond_with(ResponseTemplate::new(200).insert_header("Set-Cookie", "hop2=b; Path=/"))
        .mount(&server)
        .await;

    let client = oauth_redirect_client(Duration::from_secs(5)).expect("client");
    let url = Url::parse(&format!("{}/a", server.uri())).expect("url");
    let result = follow_oauth_redirect_chain(&client, &url, 5)
        .await
        .expect("chain");
    assert!(result.cookies.iter().any(|(n, _)| n == "hop1"));
    assert!(result.cookies.iter().any(|(n, _)| n == "hop2"));
}

#[tokio::test]
async fn errors_on_redirect_loop() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/loop"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("Location", format!("{}/loop", server.uri())),
        )
        .mount(&server)
        .await;

    let client = oauth_redirect_client(Duration::from_secs(5)).expect("client");
    let url = Url::parse(&format!("{}/loop", server.uri())).expect("url");
    let err = follow_oauth_redirect_chain(&client, &url, 10)
        .await
        .expect_err("loop");
    assert!(err.to_string().contains("loop"));
}

#[tokio::test]
async fn errors_when_max_hops_exceeded() {
    let server = MockServer::start().await;

    for i in 0..5 {
        let next = if i == 4 {
            format!("{}/end", server.uri())
        } else {
            format!("{}/hop{}", server.uri(), i + 1)
        };
        let route = if i == 0 {
            "/start".to_string()
        } else {
            format!("/hop{i}")
        };
        Mock::given(method("GET"))
            .and(path(route.as_str()))
            .respond_with(ResponseTemplate::new(302).insert_header("Location", next))
            .mount(&server)
            .await;
    }

    Mock::given(method("GET"))
        .and(path("/end"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = oauth_redirect_client(Duration::from_secs(5)).expect("client");
    let url = Url::parse(&format!("{}/start", server.uri())).expect("url");
    let err = follow_oauth_redirect_chain(&client, &url, 2)
        .await
        .expect_err("max hops");
    assert!(err.to_string().contains("max redirect hops"));
}

#[tokio::test]
async fn chain_result_matches_expected_shape() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = oauth_redirect_client(Duration::from_secs(5)).expect("client");
    let url = Url::parse(&format!("{}/ok", server.uri())).expect("url");
    let result = follow_oauth_redirect_chain(&client, &url, 3)
        .await
        .expect("chain");
    let expected = OAuthChainResult {
        hops: vec![],
        final_url: url.to_string(),
        cookies: vec![],
        final_status: 200,
    };
    assert_eq!(result.hops, expected.hops);
    assert_eq!(result.final_status, expected.final_status);
}
