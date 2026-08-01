//! Login form discovery from HTML.

pub mod html_form;
pub mod oauth;
pub mod webauthn;

pub use html_form::{
    discover_best_login_form, discover_login_forms_in_html, DiscoveredForm, FormMethod,
};
pub use oauth::{discover_best_oauth_entry, discover_oauth_entry_points, DiscoveredOAuth};
pub use webauthn::*;
