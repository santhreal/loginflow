use loginflow::capture::jwt::Jwt;

#[test]
fn register_bearer() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let mut headers = Vec::new();
    let auth_value = format!("Bearer {}", token);

    let jwt = Jwt::register_bearer(&auth_value, &mut headers).expect("Should register valid token");
    assert_eq!(jwt.payload.sub.as_deref(), Some("1234567890"));
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0, "Authorization");
    assert_eq!(headers[0].1, auth_value);
}
