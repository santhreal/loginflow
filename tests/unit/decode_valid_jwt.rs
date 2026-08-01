use loginflow::capture::jwt::Jwt;

#[test]
fn decode_valid_jwt() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let jwt = Jwt::decode(token).expect("Valid JWT should decode");
    assert_eq!(jwt.raw, token);
    assert_eq!(jwt.payload.sub.as_deref(), Some("1234567890"));
    assert_eq!(jwt.payload.iat, Some(1516239022));
    assert_eq!(jwt.payload.exp, None);
}
