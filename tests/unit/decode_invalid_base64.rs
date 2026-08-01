use loginflow::capture::jwt::Jwt;

#[test]
fn decode_invalid_base64() {
    let token = "header.invalid_base64!@#.signature";
    assert!(Jwt::decode(token).is_none());
}
