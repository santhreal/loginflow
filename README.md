# loginflow - browser-driven login discovery, form drive, MFA, and session capture into authjar

[![santh status](https://img.shields.io/badge/santh-prototype-orange)](https://santh.dev/standard)

## What it does
Loginflow drives a target from URL + credentials to a captured session in authjar. It handles HTML form discovery, browser fill/submit via runtime-headless, TOTP MFA, HTTP fast-path compatible with scald's `LoginFlow`, and canary verification.

## Quick start
```rust
use loginflow::{LoginFlow, Credentials};
use url::Url;

let flow = LoginFlow::builder().build().unwrap();
let url = Url::parse("https://example.com/login").unwrap();
let creds = Credentials {
    username: "admin".into(),
    password: secrecy::SecretString::from("password"),
    mfa_source: None,
};
```

## When to use / when not
- **Use when**: You need to dynamically discover and drive login forms.
- **Not to use when**: You only have API tokens and don't need browser logic.

## Compared to alternatives
Unlike static form post scripts, `loginflow` uses a real headless browser for discovery and handles complex SPAs. Scald's `LoginFlow` is HTTP-form-only; it does not drive a browser, cannot click an SSO redirect, cannot solve MFA, cannot wait for SPA hydration, cannot bypass a captcha gate. As a result, every authed scan that targets a real-world app either skips the auth step or hand-crafts cookies.

## How it fits in santh
It is part of `libs/runtime/` and depends on `libs/runtime/headless` and `authjar`. It is consumed by the Orchestrator and `scald` for deep authentication scans.

## Contributing
Please see `STANDARD.md` for contribution guidelines.

## License
MIT OR Apache-2.0
