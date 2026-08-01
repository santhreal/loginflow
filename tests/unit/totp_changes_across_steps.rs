//! Deterministic TOTP generation.

use loginflow::totp_code_at;

// Secret = "Hello!" (RFC 4226 HOTP test secret, base32)
const TEST_SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn totp_changes_across_steps() {
    let s0 = totp_code_at(TEST_SECRET, 0).expect("totp");
    let s_far = totp_code_at(TEST_SECRET, 100_000).expect("totp");
    assert_ne!(s0, s_far);
}
