use loginflow::capture::jwt::Jwt;

#[test]
fn decode_invalid_json() {
    let token = format!("header.{}.signature", "bm90X2pzb24"); // "not_json"
    assert!(Jwt::decode(&token).is_none());
}
