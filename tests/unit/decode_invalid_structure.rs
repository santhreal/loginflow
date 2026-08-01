use loginflow::capture::jwt::Jwt;

#[test]
fn decode_invalid_structure() {
    assert!(Jwt::decode("just.two").is_none());
    assert!(Jwt::decode("too.many.parts.here").is_none());
    assert!(Jwt::decode("").is_none());
}
