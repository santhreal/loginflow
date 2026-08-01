//! Error types for loginflow.

use thiserror::Error;

/// Form discovery failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DiscoverError {
    /// HTML could not be parsed.
    #[error("html parse failed: {0}. Fix: verify the target URL is returning well-formed HTML.")]
    Parse(String),
    /// No qualifying login form exists in the document.
    #[error("no login form in page. Fix: ensure the page contains a `<form>` with standard login fields.")]
    NoForm,
}

/// Errors from the end-to-end [`crate::LoginFlow::login`] orchestration.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LoginFlowError {
    /// Form discovery failed.
    #[error(
        "form discovery failed: {0}. Fix: verify the target URL hosts a supported login form."
    )]
    Discover(#[from] DiscoverError),
    /// Browser drive failed.
    #[error(
        "browser login drive failed: {0}. Fix: verify credentials and form selectors are correct."
    )]
    Drive(#[from] DriveError),
    /// Session capture failed.
    #[error("session capture failed: {0}. Fix: check if the site issues cookies or custom headers for auth.")]
    Capture(#[from] CaptureError),
    /// Post-login verification failed.
    #[error("login verification failed: {0}. Fix: ensure the canary URL is protected and returns expected markers.")]
    Verify(#[from] VerifyError),
    /// HTTP fast-path login failed.
    #[error("http login failed: {0}. Fix: verify HTTP-only form submission parameters.")]
    Http(#[from] HttpLoginError),
    /// No login form was found on the target page.
    #[error("no login form discovered at {url}. Fix: ensure the URL is the exact sign-in page.")]
    NoLoginForm {
        /// Page URL that was scanned.
        url: String,
    },
    /// Builder misconfiguration.
    #[error("loginflow builder: {0}. Fix: correct the builder configuration.")]
    Build(#[from] BuildError),
    /// Target URL has no host component.
    #[error("target URL has no host. Fix: use an absolute URL with a host, e.g. https://example.com/login.")]
    MissingHost,
    /// MFA was required but no source was configured.
    #[error("mfa required but credentials have no mfa_source. Fix: provide an MFA source in credentials.")]
    MfaRequired,
    /// MFA source failed.
    #[error("mfa: {0}. Fix: verify the MFA source is accessible and correct.")]
    Mfa(#[from] MfaError),
}

/// Browser drive failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DriveError {
    /// Headless runtime error.
    #[error("headless: {0}. Fix: verify chromium is installed and launchable.")]
    Headless(String),
    /// OAuth redirect chain failure.
    #[error("oauth redirect: {0}. Fix: verify the OAuth chain is not broken or looping.")]
    OAuth(String),
    /// A required field could not be filled.
    #[error("field fill failed for {field}: {details}. Fix: verify the field is visible and not disabled.")]
    FieldFill {
        /// Input name or selector.
        field: String,
        /// Failure detail.
        details: String,
    },
}

/// Session capture failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// authjar rejected the assembled session.
    #[error("authjar: {0}. Fix: verify the captured tokens are well-formed.")]
    AuthJar(#[from] authjar::AuthJarError),
    /// No cookies or headers were captured.
    #[error("empty session after login. Fix: check if the site uses a non-standard session storage mechanism.")]
    EmptySession,
}

/// Canary verification failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// HTTP fetch of the canary URL failed.
    #[error("canary request failed: {0}. Fix: verify the canary URL is reachable.")]
    Request(String),
    /// Status code did not match expectation.
    #[error("canary status {actual}, expected one of {expected:?}. Fix: verify the canary status criteria.")]
    Status {
        /// Observed HTTP status.
        actual: u16,
        /// Acceptable statuses.
        expected: Vec<u16>,
    },
    /// Body did not contain required markers.
    #[error("canary body missing markers: {missing:?}. Fix: verify the markers are correct for a logged-in state.")]
    BodyMarkers {
        /// Substrings that were not found.
        missing: Vec<String>,
    },
}

/// HTTP-only login path errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpLoginError {
    /// reqwest or URL error.
    #[error("{0}. Fix: verify the network is reachable and URL is valid.")]
    Transport(String),
    /// Target origin has no host component.
    #[error("target URL has no host. Fix: use an absolute URL with a host.")]
    MissingHost,
    /// Login response did not set cookies.
    #[error("login succeeded but no session cookies were set. Fix: the endpoint may not support HTTP-only login without JS.")]
    NoCookies,
}

/// MFA errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MfaError {
    /// TOTP generation failed.
    #[error("totp: {0}. Fix: verify the TOTP secret is base32 encoded.")]
    Totp(String),
    /// Email polling failed.
    #[error("email: {0}. Fix: verify the email polling configuration.")]
    Email(String),
    /// MFA source returned an empty code.
    #[error("empty mfa response. Fix: ensure the MFA source is supplying a valid code.")]
    Empty,
}

/// Builder errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BuildError {
    /// Browser feature disabled but browser drive was requested.
    #[error("browser feature disabled; enable `browser` or use HTTP-only targets. Fix: build with `--features browser`.")]
    BrowserUnavailable,
}
