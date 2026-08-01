use loginflow::capture::jwt::Jwt;

#[test]
fn register_bearer_invalid() {
    let mut headers = Vec::new();
    let jwt = Jwt::register_bearer("Bearer invalid.token", &mut headers);
    assert!(jwt.is_none());
    assert!(headers.is_empty(), "Should not register invalid token");
}
