//! Base32 TOTP secret normalization (spaces, dashes, lowercase, padding).

use loginflow::totp_code_at;

const CLEAN_SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn totp_normalizes_base32_secret() {
    let expected = totp_code_at(CLEAN_SECRET, 42).expect("totp clean");

    // With spaces, dashes, lowercase, and '=' padding
    let formatted = " jbswy-3dpe hpk3 pxp==  ";
    let code = totp_code_at(formatted, 42).expect("totp formatted");

    assert_eq!(code, expected, "normalized base32 secret must produce identical TOTP code");
}
