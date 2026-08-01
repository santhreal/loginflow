use loginflow::capture::jwt::Jwt;
use proptest::prelude::*;

proptest! {
    #[test]
    fn decode_rejects_strings_without_two_dots(s in "[^.]*\\.[^.]*") {
        assert!(Jwt::decode(&s).is_none());
    }
}
