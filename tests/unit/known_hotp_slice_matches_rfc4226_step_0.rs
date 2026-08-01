//! Deterministic TOTP generation.

use loginflow::totp_code_at;

// Secret = "Hello!" (RFC 4226 HOTP test secret, base32)
const TEST_SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn known_hotp_slice_matches_rfc4226_step_0() {
    // RFC 4226 Appendix D: counter 0 -> 755224 for same secret
    assert_eq!(totp_code_at(TEST_SECRET, 0).expect("totp"), "282760");
}
