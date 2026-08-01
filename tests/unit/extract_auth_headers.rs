use loginflow::capture::headers::extract_auth_headers;

#[test]
fn extracts_auth_headers_successfully() {
    let headers = vec![
        ("Host", "example.com"),
        ("Authorization", "Basic dXNlcjpwYXNz"),
        ("X-CSRF-Token", "some-csrf-token"),
        ("Accept", "application/json"),
        ("authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ];

    let extracted = extract_auth_headers(&headers);

    assert_eq!(extracted.len(), 3);

    // Basic auth should be captured as-is
    assert_eq!(extracted[0].0.to_lowercase(), "authorization");
    assert_eq!(extracted[0].1, "Basic dXNlcjpwYXNz");

    // CSRF token should be captured
    assert_eq!(extracted[1].0.to_lowercase(), "x-csrf-token");
    assert_eq!(extracted[1].1, "some-csrf-token");

    // Valid JWT Bearer token should be registered/captured
    assert_eq!(extracted[2].0.to_lowercase(), "authorization");
    assert!(extracted[2].1.starts_with("Bearer eyJhbG"));
}
