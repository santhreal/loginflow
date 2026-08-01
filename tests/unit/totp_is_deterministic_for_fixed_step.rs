//! Deterministic TOTP generation.

use loginflow::totp_code_at;

// Secret = "Hello!" (RFC 4226 HOTP test secret, base32)
const TEST_SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn totp_is_deterministic_for_fixed_step() {
    let a = totp_code_at(TEST_SECRET, 1).expect("totp");
    let b = totp_code_at(TEST_SECRET, 1).expect("totp");
    assert_eq!(a, b);
    assert_eq!(a.len(), 6);
    assert!(a.chars().all(|c| c.is_ascii_digit()));
}
