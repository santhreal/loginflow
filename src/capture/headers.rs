//! HTTP authentication header extraction.

use crate::capture::jwt::Jwt;

/// Extract authentication-relevant headers (e.g., `Authorization` or `X-CSRF-Token`).
///
/// Looks for bearer tokens and CSRF tokens in the provided header list, and
/// returns a vector of valid auth headers ready for session capture.
///
/// # Arguments
///
/// * `headers` - A slice of header name and value pairs.
///
/// # Returns
///
/// Returns a vector of key-value pairs representing the extracted authentication headers.
pub fn extract_auth_headers(headers: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut auth_headers = Vec::new();

    for &(name, value) in headers {
        if name.eq_ignore_ascii_case("authorization") {
            // If it's a Bearer token, we attempt to decode and register it.
            // If it's valid JWT, it will be added to auth_headers.
            // If it's not a JWT, we might still want to capture it depending on policy,
            // but for loginflow we specifically register valid JWT bearer tokens.
            if value.to_lowercase().starts_with("bearer ") {
                Jwt::register_bearer(value, &mut auth_headers);
            } else {
                // Non-bearer authorization (e.g., Basic), capture as is.
                auth_headers.push((name.to_string(), value.to_string()));
            }
        } else if name.eq_ignore_ascii_case("x-csrf-token") {
            auth_headers.push((name.to_string(), value.to_string()));
        }
    }

    auth_headers
}
