//! Loginflow drives a target from URL + credentials to a captured session in authjar.
//!
//! v0.1 substrate: HTML form discovery, browser fill/submit via runtime-headless,
//! TOTP MFA, HTTP fast-path compatible with scald's `LoginFlow`, and canary verification.
//!
//! ## Safe Defaults
//! - **Input size**: HTTP bodies are bounded to 1MB by default.
//! - **Recursion depth**: DOM tree recursion is bounded to 128 levels.
//! - **Outbound network**: Loopback and private IP space are allowed for dev targets, but can be restricted via stealth profiles.
//! - **Process spawning**: Browser launches use runtime-headless's canonical stealth launch defaults and remain overrideable.
//! - **Filesystem writes**: Output is written strictly to the configured authjar store; no other filesystem access occurs.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

pub mod capture;
pub mod discover;
pub mod drive;
pub mod error;
pub mod http_fastpath;
mod http_identity;
pub mod mfa;
pub mod verify;

pub use capture::{capture_from_auth_session, CapturedSession, ScaldAuth};
pub use discover::{
    discover_best_login_form, discover_best_oauth_entry, discover_login_forms_in_html,
    discover_oauth_entry_points, DiscoveredForm, DiscoveredOAuth, FormMethod,
};
#[cfg(feature = "browser")]
pub use drive::webauthn::{respond_to_webauthn_challenge, VirtualAuthenticatorConfig};
pub use drive::{
    follow_oauth_redirect_chain, oauth_redirect_client, CaptchaChallenge, CaptchaError,
    CaptchaKind, CaptchaSolution, CaptchaSolver, OAuthChainResult, RedirectHop, StubCaptchaSolver,
};
#[cfg(all(feature = "browser", feature = "captchaforge"))]
pub use drive::{solve_via_captchaforge, CaptchaForgeSolver};
pub use error::{
    BuildError, CaptureError, DiscoverError, DriveError, HttpLoginError, LoginFlowError, MfaError,
    VerifyError,
};
pub use http_fastpath::{eligible_for_http_fastpath, perform_http_login, ScaldLoginFlow};
pub use mfa::{totp_code_at, MfaPrompt, MfaResponse, MfaSource, TotpMfaSource, TotpSecret};
pub use verify::{verify_canary, CanaryConfig};

#[cfg(feature = "stealth")]
pub use guise::ProfileBundle;

use authjar::SessionStore;
use http_identity::HttpIdentity;
use secrecy::SecretString;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use url::Url;

#[cfg(feature = "browser")]
use runtime_headless::{BrowserLaunchOptions, BrowserRuntime, Page};

/// Credentials for a single login attempt.
#[derive(Clone)]
pub struct Credentials {
    /// Username or email.
    pub username: String,
    /// Password (never logged).
    pub password: SecretString,
    /// Optional MFA provider (TOTP, etc.).
    pub mfa_source: Option<Arc<dyn MfaSource>>,
}

/// Configured login driver (opaque builder output).
pub struct LoginFlow {
    insecure: bool,
    session_name: String,
    prefer_http: bool,
    force_browser: bool,
    http_timeout: Duration,
    canary: Option<CanaryConfig>,
    auth_store: Option<Arc<Mutex<SessionStore>>>,
    #[allow(dead_code)]
    captcha_solver: Option<Arc<dyn CaptchaSolver>>,
    #[cfg(feature = "stealth")]
    stealth_profile: Option<ProfileBundle>,
    #[cfg(feature = "browser")]
    browser: Option<Arc<BrowserRuntime>>,
    #[cfg(feature = "browser")]
    launch_options: BrowserLaunchOptions,
}

/// Builder for [`LoginFlow`].
pub struct LoginFlowBuilder {
    insecure: bool,
    session_name: String,
    prefer_http: bool,
    force_browser: bool,
    http_timeout: Duration,
    canary: Option<CanaryConfig>,
    auth_store: Option<Arc<Mutex<SessionStore>>>,
    captcha_solver: Option<Arc<dyn CaptchaSolver>>,
    #[cfg(feature = "stealth")]
    stealth_profile: Option<ProfileBundle>,
    #[cfg(feature = "browser")]
    browser: Option<Arc<BrowserRuntime>>,
    #[cfg(feature = "browser")]
    launch_options: BrowserLaunchOptions,
}

impl LoginFlow {
    /// Start a builder with default options.
    #[must_use]
    pub fn builder() -> LoginFlowBuilder {
        LoginFlowBuilder::default()
    }

    fn http_identity(&self) -> HttpIdentity {
        #[cfg(feature = "stealth")]
        {
            self.stealth_profile
                .map(HttpIdentity::Stealth)
                .unwrap_or_default()
        }
        #[cfg(not(feature = "stealth"))]
        {
            HttpIdentity::None
        }
    }

    /// Discover a login form from the current page HTML (browser feature).
    ///
    /// # Errors
    ///
    /// Returns [`DiscoverError`] when HTML cannot be fetched or parsed.
    #[cfg(feature = "browser")]
    pub async fn discover_form(
        &self,
        page: &Page,
    ) -> Result<Option<DiscoveredForm>, DiscoverError> {
        let html =
            runtime_headless::evaluate_script_value(page, "document.documentElement.outerHTML")
                .await
                .map_err(|e| DiscoverError::Parse(e.to_string()))?;
        let page_url = page
            .url()
            .await
            .map_err(|e| DiscoverError::Parse(e.to_string()))?
            .ok_or(DiscoverError::Parse("page has no url".into()))?;
        let url = Url::parse(&page_url).map_err(|e| DiscoverError::Parse(e.to_string()))?;
        discover_best_login_form(&html, &url)
    }

    /// Drive a previously discovered form in an open page.
    ///
    /// # Errors
    ///
    /// Returns [`DriveError`] when fill/submit fails.
    #[cfg(feature = "browser")]
    pub async fn drive_form(
        &self,
        page: &Page,
        form: &DiscoveredForm,
        credentials: &Credentials,
    ) -> Result<(), DriveError> {
        let page_url = page
            .url()
            .await
            .map_err(|e| DriveError::Headless(e.to_string()))?
            .unwrap_or_default();
        drive::drive_html_form(
            page,
            &page_url,
            form,
            &credentials.username,
            &credentials.password,
            credentials.mfa_source.as_ref(),
        )
        .await
    }

    /// End-to-end login: discover → HTTP or browser → capture → optional canary.
    ///
    /// # Errors
    ///
    /// Returns [`LoginFlowError`] on discovery, drive, capture, or verification failure.
    pub async fn login(
        &self,
        target_url: &Url,
        credentials: &Credentials,
    ) -> Result<CapturedSession, LoginFlowError> {
        if target_url.host_str().is_none() {
            return Err(LoginFlowError::MissingHost);
        }
        let html = self.fetch_page_html(target_url).await?;
        let form = discover_best_login_form(&html, target_url)?.ok_or_else(|| {
            LoginFlowError::NoLoginForm {
                url: target_url.to_string(),
            }
        })?;

        if form.has_totp_field && credentials.mfa_source.is_none() {
            return Err(LoginFlowError::MfaRequired);
        }

        let use_http = eligible_for_http_fastpath(&form, self.force_browser)
            && (self.prefer_http || !self.force_browser);

        let session_name = self.session_name.clone();
        let captured = if use_http {
            let mfa_code = if form.has_totp_field {
                let source = credentials
                    .mfa_source
                    .as_ref()
                    .ok_or(LoginFlowError::MfaRequired)?;
                let resp = source.fetch(&MfaPrompt::Totp { field_name: None }).await?;
                Some(resp.code)
            } else {
                None
            };
            let flow = ScaldLoginFlow::from_discovered(
                &form,
                &credentials.username,
                &credentials.password,
                mfa_code.as_deref(),
            );
            let mut captured = http_fastpath::perform_http_login_with_identity(
                &flow,
                &[],
                target_url,
                self.http_timeout,
                self.http_identity(),
                self.insecure,
            )
            .await
            .map_err(LoginFlowError::Http)?;
            captured.auth_session.name = session_name;
            captured
        } else {
            #[cfg(feature = "browser")]
            {
                self.login_via_browser(target_url, &form, credentials)
                    .await?
            }
            #[cfg(not(feature = "browser"))]
            {
                return Err(LoginFlowError::Build(BuildError::BrowserUnavailable));
            }
        };

        if let Some(ref canary) = self.canary {
            verify::verify_canary_with_identity(
                &captured.scald_auth,
                canary,
                self.http_identity(),
                self.insecure,
            )
            .await
            .map_err(LoginFlowError::Verify)?;
        }

        if let Some(store) = &self.auth_store {
            captured.persist_shared(store);
        }

        Ok(captured)
    }

    #[cfg(feature = "browser")]
    async fn login_via_browser(
        &self,
        target_url: &Url,
        form: &DiscoveredForm,
        credentials: &Credentials,
    ) -> Result<CapturedSession, LoginFlowError> {
        let runtime = match &self.browser {
            Some(rt) => Arc::clone(rt),
            None => Arc::new(
                BrowserRuntime::launch(&self.launch_options)
                    .await
                    .map_err(|e| LoginFlowError::Drive(DriveError::Headless(e.to_string())))?,
            ),
        };

        #[cfg(feature = "stealth")]
        let page = if let Some(bundle) = self.stealth_profile {
            guise::cdp::open_profiled_page(runtime.browser(), target_url.as_str(), bundle.browser)
                .await
                .map_err(|e| LoginFlowError::Drive(DriveError::Headless(e.to_string())))?
        } else {
            runtime
                .browser()
                .new_page(target_url.as_str())
                .await
                .map_err(|e| LoginFlowError::Drive(DriveError::Headless(e.to_string())))?
        };

        #[cfg(not(feature = "stealth"))]
        let page = runtime
            .browser()
            .new_page(target_url.as_str())
            .await
            .map_err(|e| LoginFlowError::Drive(DriveError::Headless(e.to_string())))?;

        self.drive_form(&page, form, credentials)
            .await
            .map_err(LoginFlowError::Drive)?;

        let document_cookie = runtime_headless::evaluate_script_value(&page, "document.cookie")
            .await
            .map_err(|e| LoginFlowError::Drive(DriveError::Headless(e.to_string())))?;

        let domain = target_url.host_str().ok_or(LoginFlowError::MissingHost)?;
        capture::capture_from_document_cookies(&self.session_name, domain, &document_cookie)
            .map_err(LoginFlowError::Capture)
    }
}

impl LoginFlowBuilder {
    /// Session name used in authjar (default `"loginflow"`).
    #[must_use]
    pub fn session_name(mut self, name: impl Into<String>) -> Self {
        self.session_name = name.into();
        self
    }

    /// Prefer HTTP fast-path when the discovered form is simple.
    #[must_use]
    pub fn prefer_http(mut self, prefer: bool) -> Self {
        self.prefer_http = prefer;
        self
    }

    /// Force browser drive even for simple forms.
    #[must_use]
    pub fn force_browser(mut self, force: bool) -> Self {
        self.force_browser = force;
        self
    }

    /// HTTP login / fetch timeout.
    #[must_use]
    pub fn http_timeout(mut self, timeout: Duration) -> Self {
        self.http_timeout = timeout;
        self
    }

    /// Disable TLS certificate verification for all outbound HTTP in this flow.
    ///
    /// This is off by default; enabling it logs a loud warning when credentials
    /// are submitted. Use only for testing against self-signed endpoints.
    #[must_use]
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// Post-login canary GET configuration.
    #[must_use]
    pub fn with_canary(mut self, canary: CanaryConfig) -> Self {
        self.canary = Some(canary);
        self
    }

    /// Persist captured sessions into authjar (`Arc<Mutex<SessionStore>>` for shared stores).
    #[must_use]
    pub fn with_authjar(mut self, store: Arc<Mutex<SessionStore>>) -> Self {
        self.auth_store = Some(store);
        self
    }

    /// Captcha gate solver (stub or captchaforge-backed).
    #[must_use]
    pub fn with_captcha_solver(mut self, solver: Arc<dyn CaptchaSolver>) -> Self {
        self.captcha_solver = Some(solver);
        self
    }

    /// Browser + TLS fingerprint bundle for HTTP fetch and browser drive.
    #[cfg(feature = "stealth")]
    #[must_use]
    pub fn with_stealth_profile(mut self, profile: ProfileBundle) -> Self {
        self.stealth_profile = Some(profile);
        self
    }

    /// Reuse an existing headless browser runtime.
    #[cfg(feature = "browser")]
    #[must_use]
    pub fn with_browser(mut self, browser: Arc<BrowserRuntime>) -> Self {
        self.browser = Some(browser);
        self
    }

    /// Launch options when no shared browser is supplied.
    #[cfg(feature = "browser")]
    #[must_use]
    pub fn with_launch_options(mut self, options: BrowserLaunchOptions) -> Self {
        self.launch_options = options;
        self
    }

    /// Build the [`LoginFlow`] driver.
    ///
    /// # Errors
    ///
    /// Currently always succeeds; reserved for future validation.
    pub fn build(self) -> Result<LoginFlow, BuildError> {
        Ok(LoginFlow {
            insecure: self.insecure,
            session_name: if self.session_name.is_empty() {
                "loginflow".to_string()
            } else {
                self.session_name
            },
            prefer_http: self.prefer_http,
            force_browser: self.force_browser,
            http_timeout: self.http_timeout,
            canary: self.canary,
            auth_store: self.auth_store,
            captcha_solver: self.captcha_solver,
            #[cfg(feature = "stealth")]
            stealth_profile: self.stealth_profile,
            #[cfg(feature = "browser")]
            browser: self.browser,
            #[cfg(feature = "browser")]
            launch_options: self.launch_options,
        })
    }
}

impl Default for LoginFlowBuilder {
    fn default() -> Self {
        Self {
            insecure: false,
            session_name: "loginflow".to_string(),
            prefer_http: true,
            force_browser: false,
            http_timeout: Duration::from_secs(30),
            canary: None,
            auth_store: None,
            captcha_solver: None,
            #[cfg(feature = "stealth")]
            stealth_profile: None,
            #[cfg(feature = "browser")]
            browser: None,
            #[cfg(feature = "browser")]
            launch_options: BrowserLaunchOptions::default_stealth(),
        }
    }
}

impl LoginFlow {
    async fn fetch_page_html(&self, url: &Url) -> Result<String, LoginFlowError> {
        let client_builder = reqwest::Client::builder()
            .timeout(self.http_timeout)
            .redirect(reqwest::redirect::Policy::limited(5))
            .danger_accept_invalid_certs(self.insecure);

        let client_builder =
            http_identity::apply_to_client_builder(client_builder, self.http_identity())
                .map_err(|e| LoginFlowError::Http(HttpLoginError::Transport(e)))?;

        let client = client_builder
            .build()
            .map_err(|e| LoginFlowError::Http(HttpLoginError::Transport(e.to_string())))?;

        let response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| LoginFlowError::Http(HttpLoginError::Transport(e.to_string())))?;

        response
            .text()
            .await
            .map_err(|e| LoginFlowError::Http(HttpLoginError::Transport(e.to_string())))
    }
}

#[cfg(all(test, feature = "browser"))]
mod tests {
    use super::*;

    #[test]
    fn builder_default_launch_options_delegate_runtime_stealth_profile() {
        let flow = LoginFlowBuilder::default()
            .build()
            .expect("default loginflow builder should build");
        let expected = BrowserLaunchOptions::default_stealth();

        assert_eq!(flow.launch_options.window_width, expected.window_width);
        assert_eq!(flow.launch_options.window_height, expected.window_height);
        assert_eq!(flow.launch_options.no_sandbox, expected.no_sandbox);
        assert_eq!(
            flow.launch_options.disable_default_args,
            expected.disable_default_args
        );
        assert_eq!(flow.launch_options.headed, expected.headed);
        assert_eq!(
            flow.launch_options.request_timeout,
            expected.request_timeout
        );
        assert_eq!(
            flow.launch_options.chrome_executable,
            expected.chrome_executable
        );
        assert_eq!(
            flow.launch_options.new_headless_mode,
            expected.new_headless_mode
        );
        assert_eq!(flow.launch_options.extra_args, expected.extra_args);
        assert_eq!(flow.launch_options.user_data_dir, expected.user_data_dir);
    }
}

#[cfg(all(test, feature = "stealth"))]
mod stealth_http_tests {
    use super::*;
    use guise::{ProfileBundle, StealthProfile};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn fetch_page_html_sends_profile_navigation_headers() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have address");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("server should accept");
            let mut buf = [0_u8; 4096];
            let n = socket.read(&mut buf).await.expect("server should read");
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 26\r\n\r\n<html><form></form></html>",
                )
                .await
                .expect("server should respond");
            request
        });

        let flow = LoginFlow::builder()
            .with_stealth_profile(ProfileBundle::for_browser(StealthProfile::FirefoxWindows))
            .build()
            .expect("flow should build");
        let html = flow
            .fetch_page_html(&Url::parse(&format!("http://{addr}/login")).expect("valid url"))
            .await
            .expect("page fetch should succeed");
        let request = server.await.expect("server task should finish");
        let request_lower = request.to_ascii_lowercase();
        let facts = guise::fingerprint::profile_facts(StealthProfile::FirefoxWindows);

        assert_eq!(html, "<html><form></form></html>");
        assert!(request_lower.contains("user-agent: mozilla/5.0"));
        assert!(
            request_lower.contains(&facts.user_agent.to_ascii_lowercase()),
            "loginflow HTTP stealth UA drifted from shared profile: {request}"
        );
        assert!(
            request_lower.contains(&format!("accept: {}", facts.accept).to_ascii_lowercase()),
            "loginflow HTTP stealth Accept header drifted from shared profile: {request}"
        );
        assert!(
            request_lower.contains(
                &format!("accept-language: {}", facts.accept_language).to_ascii_lowercase()
            ),
            "loginflow HTTP stealth Accept-Language header drifted from shared profile: {request}"
        );
        assert!(
            !request_lower.contains("accept-encoding:"),
            "loginflow reqwest build does not enable transparent decompression, so stealth HTTP defaults must not advertise compression: {request}"
        );
    }
}
