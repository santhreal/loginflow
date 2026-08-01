//! Login execution: HTTP OAuth chains and browser form drive.

mod captcha;
mod oauth;
#[cfg(feature = "browser")]
pub mod webauthn;

#[cfg(feature = "browser")]
pub mod html_form;
#[cfg(feature = "browser")]
pub mod hydration;

#[cfg(all(feature = "browser", feature = "captchaforge"))]
pub use captcha::{solve_via_captchaforge, CaptchaForgeSolver};
pub use captcha::{
    CaptchaChallenge, CaptchaError, CaptchaKind, CaptchaSolution, CaptchaSolver, StubCaptchaSolver,
};
#[cfg(feature = "browser")]
pub use html_form::drive_html_form;
#[cfg(feature = "browser")]
pub use hydration::{wait_for_spa_hydration, HydrationWait};
pub use oauth::{
    follow_oauth_redirect_chain, oauth_redirect_client, OAuthChainResult, RedirectHop,
};
