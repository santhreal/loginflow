//! [`CapturedSession`] bridges authjar and scald `Auth`.

use crate::error::CaptureError;
use authjar::{AuthSession, SessionStore};
use serde::{Deserialize, Serialize};

/// scald-compatible `Auth { cookies, headers }` wire shape.
///
/// `Debug` redacts cookie values and header values; both carry credentials.
/// Serialization is unaffected, scanners still receive the real values.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScaldAuth {
    /// `Set-Cookie` fragments as `name=value` pairs for scanners.
    pub cookies: Vec<String>,
    /// Extra auth headers (e.g. `Authorization`, `X-CSRF-Token`).
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for ScaldAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cookie_names: Vec<&str> = self
            .cookies
            .iter()
            .map(|pair| pair.split('=').next().unwrap_or(pair.as_str()))
            .collect();
        let header_names: Vec<&str> = self.headers.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("ScaldAuth")
            .field("cookies", &cookie_names)
            .field("headers", &header_names)
            .finish()
    }
}

/// Login result: authjar session + scald hand-off view.
#[derive(Debug, Clone)]
pub struct CapturedSession {
    /// Canonical authjar session.
    pub auth_session: AuthSession,
    /// scald / orchestrator wire auth.
    pub scald_auth: ScaldAuth,
}

impl CapturedSession {
    /// Persist into a configured [`SessionStore`] under the session name.
    pub fn persist(&self, store: &mut SessionStore) {
        store.add(self.auth_session.clone());
    }

    /// Persist into a shared, lock-guarded store, recovering a poisoned mutex.
    ///
    /// A poisoned lock (another thread panicked while holding it) is RECOVERED
    /// and the session is still written, never silently dropped. The former
    /// `if let Ok(guard) = store.lock()` call site skipped the persist on poison
    /// and returned as though it had succeeded, so a freshly captured auth
    /// session vanished from the shared store with no operator-visible signal
    /// (Law 10). [`SessionStore::add`] is a plain insert, so a poisoned guard's
    /// contents are still consistent to write through.
    pub fn persist_shared(&self, store: &std::sync::Mutex<SessionStore>) {
        let mut guard = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.persist(&mut guard);
    }
}

/// Build capture from an authjar session and optional extra headers.
///
/// # Errors
///
/// Returns [`CaptureError::EmptySession`] when no cookies are present.
pub fn capture_from_auth_session(
    session: AuthSession,
    domain: &str,
    extra_headers: Vec<(String, String)>,
) -> Result<CapturedSession, CaptureError> {
    let settings = authjar::SessionSettings::default();
    let header = session.cookie_header(domain, &settings);
    let cookies = if header.is_empty() {
        Vec::new()
    } else {
        header
            .split(';')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect()
    };

    if cookies.is_empty() && extra_headers.is_empty() {
        return Err(CaptureError::EmptySession);
    }

    let mut headers = extra_headers;
    for token in &session.csrf_tokens {
        headers.push(("X-CSRF-Token".to_string(), token.value.clone()));
    }

    Ok(CapturedSession {
        scald_auth: ScaldAuth { cookies, headers },
        auth_session: session,
    })
}

/// Ingest HTTP response headers into a new [`CapturedSession`].
///
/// # Errors
///
/// Returns [`CaptureError`] when ingestion or capture fails.
pub fn capture_from_http_headers(
    session_name: &str,
    domain: &str,
    status: u16,
    headers: &[(&str, &str)],
    body: &str,
) -> Result<CapturedSession, CaptureError> {
    let init = authjar::SessionInit::new();
    let session = init
        .ingest(session_name, domain, status, headers, body)
        .map_err(CaptureError::AuthJar)?;
    capture_from_auth_session(session, domain, Vec::new())
}

/// Parse `document.cookie` style pairs from browser evaluation.
///
/// # Errors
///
/// Returns [`CaptureError::EmptySession`] when no cookies are parsed.
#[cfg(feature = "browser")]
pub fn capture_from_document_cookies(
    session_name: &str,
    domain: &str,
    document_cookie: &str,
) -> Result<CapturedSession, CaptureError> {
    let mut session = AuthSession::new(session_name);
    for part in document_cookie.split(';') {
        let part = part.trim();
        if let Some((name, value)) = part.split_once('=') {
            let name = name.trim();
            let value = value.trim();
            if !name.is_empty() {
                session.add_cookie(name, value, domain);
            }
        }
    }
    capture_from_auth_session(session, domain, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn captured(name: &str) -> CapturedSession {
        CapturedSession {
            auth_session: AuthSession::new(name),
            scald_auth: ScaldAuth::default(),
        }
    }

    #[test]
    fn persist_shared_writes_through_a_poisoned_mutex() {
        // Regression: the old `if let Ok(guard) = store.lock()` silently skipped
        // the persist when the mutex was poisoned, dropping a captured session
        // with no signal. persist_shared must recover the poisoned guard and
        // still write the session.
        let store = Arc::new(Mutex::new(SessionStore::new()));

        // Poison the mutex: panic while holding the lock on another thread.
        let poisoner = Arc::clone(&store);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().unwrap();
            panic!("poison the auth store");
        })
        .join();
        assert!(store.is_poisoned(), "precondition: mutex must be poisoned");

        captured("recovered-session").persist_shared(&store);

        let guard = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            guard.get("recovered-session").is_some(),
            "session must be persisted even through a poisoned lock"
        );
        assert_eq!(guard.len(), 1);
    }

    #[test]
    fn persist_shared_writes_through_a_healthy_mutex() {
        let store = Mutex::new(SessionStore::new());
        captured("s").persist_shared(&store);
        assert!(store.lock().unwrap().get("s").is_some());
    }
}
