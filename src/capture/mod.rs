//! Post-login session capture into authjar and scald wire types.

pub mod headers;
pub mod jwt;
pub mod session;

pub use headers::*;
pub use jwt::*;
#[cfg(feature = "browser")]
pub use session::capture_from_document_cookies;
pub use session::{
    capture_from_auth_session, capture_from_http_headers, CapturedSession, ScaldAuth,
};
