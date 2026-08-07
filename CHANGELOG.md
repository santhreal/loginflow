# Changelog

## [0.1.3] - 2026-08-07

### Fixed

- Preserved lossy UTF-8 response header values in HTTP fast-path (`src/http_fastpath.rs`) to prevent dropping non-ASCII header bytes to empty string.
- Normalized base32 TOTP secret input in `totp_code_at` (`src/mfa/totp.rs`) to handle whitespace, hyphens, lowercase characters, and `=` padding.

## [0.1.2] - 2026-08-07

### Fixed

- Corrected missing `method` attribute fallback in HTML form discovery (`src/discover/html_form.rs`) to default to `GET` per HTML5 specification instead of `POST`.
- Updated form ranking score (`score_form`) to prioritize principled login signals (password fields, submit controls, CSRF tokens, action URL hints) over field-name character counts and missing CSRF bonuses.
- Restructured input classification in `analyze_form` so honeypot attributes are evaluated once up-front and CSRF tokens are captured even when present in visible text inputs.
- Updated `rust-toolchain.toml` channel to 1.88 matching `Cargo.toml` MSRV requirement.

## 0.1.1 - 2026-07-31

### Security

- `Debug` for `TotpSecret`, `Jwt`, `MfaResponse`, `CaptchaSolution`, and
  `ScaldAuth` now redacts secrets (TOTP seeds, raw tokens, OTP codes, captcha
  tokens, cookie and header values) so login artifacts no longer leak into
  debug logs. `TotpSecret` also zeroizes its stored secret on drop.

### Fixed

- The two `respond_to_webauthn_challenge` integration tests targeted a
  removed stub API and did not compile under the `browser` feature. They now
  drive the real CDP virtual-authenticator flow against live Chromium when
  one is available.
- Builds against the decoupled `runtime-headless` (calyx dependency removed).
- A malformed embedded `oauth_providers.toml` no longer panics the OAuth
  discovery accessor. The parse result is cached in a `LazyLock` and a parse
  failure is surfaced to callers as `DiscoverError::Parse`.
- The MFA polling sources (`sms_relay`, `email_link`) no longer panic when the
  shared `reqwest` client fails to build. The client is built once behind a
  `LazyLock` and a build failure surfaces as an `MfaError` at the poll site.
- The `spa_hydration` browser test imported the hydration helpers from the
  crate root instead of `drive`, and served its fixture page as `text/plain`
  (wiremock's `set_body_string` overrides the inserted `content-type`), so the
  page script never ran and the hydration wait could never succeed. It now
  uses `set_body_raw` and passes against live Chromium.

## 0.1.0 - 2026-05-25

### Added

- New crate `loginflow` (publish=true): HTML form discovery with CSRF + honeypot skip, browser fill/submit via runtime-headless, TOTP MFA, session capture to authjar + scald `Auth`, canary verification, scald-compatible HTTP fast-path.
- Tier-B sample `tier_b/form_patterns.toml`.
- Unit tests: HTML discovery fixtures, deterministic TOTP, HTTP fast-path / `LoginFlow::login` orchestration.

### Notes

- OAuth discovery (`discover/oauth.rs`) and HTTP redirect drive (`drive/oauth.rs`) with `tier_b/oauth_providers.toml`.
- Captcha dispatch trait + `StubCaptchaSolver`; optional `captchaforge` feature calls `solve_via_captchaforge`.
- `loginflow` CLI binary: `login --target --credentials --out session.json`.
- 41 tests (29 net-new vs v0.1.0 substrate).
- WebAuthn, browser SSO drive, secbench verifier, and full phase-doc corpus/live suites remain follow-ups.
