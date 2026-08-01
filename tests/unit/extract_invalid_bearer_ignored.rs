use loginflow::capture::headers::extract_auth_headers;

#[test]
fn extract_invalid_bearer_ignored() {
    let headers = vec![("Authorization", "Bearer invalid_token_here")];

    let extracted = extract_auth_headers(&headers);
    // Invalid JWT bearer tokens are not captured by extract_auth_headers
    assert_eq!(extracted.len(), 0);
}
