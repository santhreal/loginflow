//! JWT bearer token extraction and decoding.

use serde::{Deserialize, Serialize};

/// Payload extracted from a decoded JWT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JwtPayload {
    /// Subject identifier.
    #[serde(default)]
    pub sub: Option<String>,
    /// Issuer.
    #[serde(default)]
    pub iss: Option<String>,
    /// Expiration timestamp (seconds since epoch).
    #[serde(default)]
    pub exp: Option<u64>,
    /// Issued-at timestamp (seconds since epoch).
    #[serde(default)]
    pub iat: Option<u64>,
    /// Audience.
    #[serde(default)]
    pub aud: Option<String>,
}

/// A parsed JSON Web Token.
///
/// `Debug` redacts the raw token: a JWT is a bearer credential and must not
/// leak into logs. The decoded payload stays visible for diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct Jwt {
    /// The raw token string.
    pub raw: String,
    /// The deserialized payload.
    pub payload: JwtPayload,
}

impl std::fmt::Debug for Jwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwt")
            .field("raw", &"[redacted]")
            .field("payload", &self.payload)
            .finish()
    }
}

impl Jwt {
    /// Decode a JWT token into its parts and extract the payload.
    ///
    /// # Returns
    ///
    /// Returns `Some(Jwt)` if the token is structurally valid and the payload
    /// can be decoded. Returns `None` if the token is malformed.
    pub fn decode(token: &str) -> Option<Self> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let payload_b64 = parts[1];
        let payload_bytes = decode_base64url(payload_b64)?;
        let payload: JwtPayload = serde_json::from_slice(&payload_bytes).ok()?;

        Some(Self {
            raw: token.to_string(),
            payload,
        })
    }

    /// Register a bearer token by decoding it and, if valid, appending it to the
    /// given headers list.
    pub fn register_bearer(auth_value: &str, headers: &mut Vec<(String, String)>) -> Option<Self> {
        let token = if let Some(stripped) = auth_value.strip_prefix("Bearer ") {
            stripped.trim()
        } else {
            auth_value.trim()
        };

        if let Some(jwt) = Self::decode(token) {
            headers.push(("Authorization".to_string(), format!("Bearer {}", token)));
            Some(jwt)
        } else {
            None
        }
    }
}

/// Decode a Base64URL-encoded string into bytes without padding.
fn decode_base64url(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut buffer = 0u32;
    let mut bits = 0;

    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue, // Ignore padding if present
            _ => return None,
        };

        buffer = (buffer << 6) | (val as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }

    Some(out)
}
