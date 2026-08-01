use loginflow::capture::jwt::Jwt;
use proptest::prelude::*;

proptest! {
    #[test]
    fn does_not_panic_on_any_string(s in "\\PC*") {
        let _ = Jwt::decode(&s);
    }
}
