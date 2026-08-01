//! `loginflow login --target URL --credentials creds.toml --out session.json`

use authjar::AuthSession;
use clap::Subcommand;
use loginflow::{Credentials, LoginFlowBuilder, LoginFlowError, ScaldAuth};
use santh_cli::{GlobalFlags, SanthCli, SanthExitCode};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use url::Url;
use zeroize::Zeroize;

struct LoginflowCli;

#[derive(Subcommand)]
enum Commands {
    /// Drive login end-to-end and write session JSON.
    Login {
        /// Target login page URL.
        #[arg(long)]
        target: String,
        /// Credentials TOML (`username`, `password`, optional `totp_secret`).
        #[arg(long)]
        credentials: PathBuf,
        /// Output session JSON path.
        #[arg(long)]
        out: PathBuf,
        /// HTTP / fetch timeout in seconds.
        #[arg(long, default_value = "30")]
        timeout_secs: u64,
        /// Disable TLS certificate verification (insecure; default verifies).
        #[arg(long)]
        insecure: bool,
    },
}

#[derive(Debug, Deserialize)]
struct CredentialsFile {
    username: String,
    password: SecretString,
    totp_secret: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionExport {
    session_name: String,
    domain: String,
    auth_session: AuthSession,
    scald_auth: ScaldAuth,
}

impl SanthCli for LoginflowCli {
    type Subcommand = Commands;

    fn tool_name() -> &'static str {
        "loginflow"
    }

    fn tool_version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn tool_description() -> &'static str {
        "Browser-driven login discovery, form drive, MFA, and session capture into authjar"
    }

    fn run(_globals: GlobalFlags, subcommand: Self::Subcommand) -> ExitCode {
        match subcommand {
            Commands::Login {
                target,
                credentials,
                out,
                timeout_secs,
                insecure,
            } => match run_login(target, credentials, out, timeout_secs, insecure) {
                Ok(()) => SanthExitCode::Success.into(),
                Err(e) => {
                    tracing::error!("Login failed: {}", e);
                    SanthExitCode::UserError.into()
                }
            },
        }
    }
}

fn run_login(
    target: String,
    credentials_path: PathBuf,
    out_path: PathBuf,
    timeout_secs: u64,
    insecure: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut creds_toml = fs::read_to_string(&credentials_path)?;
    let creds_file: CredentialsFile = toml::from_str(&creds_toml)?;
    // Overwrite the raw credentials file buffer before it leaves this scope.
    // `SecretString` keeps the password zeroized on Drop; this ensures the
    // plaintext does not also linger in the temporary `String`.
    creds_toml.zeroize();

    let mfa_source = creds_file.totp_secret.map(|secret| {
        std::sync::Arc::new(loginflow::TotpMfaSource::new(secret))
            as std::sync::Arc<dyn loginflow::MfaSource>
    });

    let credentials = Credentials {
        username: creds_file.username,
        password: creds_file.password,
        mfa_source,
    };

    let target_url = Url::parse(&target)?;
    let domain = target_url
        .host_str()
        .ok_or(LoginFlowError::MissingHost)?
        .to_string();

    let driver = LoginFlowBuilder::default()
        .prefer_http(true)
        .http_timeout(Duration::from_secs(timeout_secs))
        .insecure(insecure)
        .build()?;

    let rt = tokio::runtime::Runtime::new()?;
    let captured = rt.block_on(driver.login(&target_url, &credentials))?;

    let export = SessionExport {
        session_name: captured.auth_session.name.clone(),
        domain,
        auth_session: captured.auth_session,
        scald_auth: captured.scald_auth,
    };

    let json = serde_json::to_string_pretty(&export)?;
    fs::write(&out_path, json)?;

    tracing::info!(
        "wrote session for {:?} to {} ({} cookies)",
        export.session_name,
        out_path.display(),
        export.auth_session.cookie_count()
    );
    Ok(())
}

fn main() -> ExitCode {
    santh_cli::santh_main::<LoginflowCli>()
}
