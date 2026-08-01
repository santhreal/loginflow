# `loginflow` Specification

## Architecture
`loginflow` drives an end-to-end authentication process spanning initial credential supply, HTML form and WebAuthn challenge discovery, session storage handling (via `authjar`), and token extraction. 

## Guarantees & Invariants
- **Input size**: HTTP bodies are bounded to 1MB by default.
- **Recursion depth**: DOM tree recursion is bounded to 128 levels.
- **Outbound network**: Loopback and private IP space are allowed for dev targets, but restricted via stealth profiles.
- **Process spawning**: Headless browsers are spawned with `--no-sandbox` explicitly disabled unless overridden.
- **JWT Parsing**: Extractors explicitly reject malformed Base64URL encodings and unbalanced parts.

## External API Contract
- The CLI is powered by `SanthCli`, enforcing unified standard output modes (`json`, `sarif`, `human`) and `--quiet` operations.
- CLI exits follow the `SanthExitCode` standard (`0` = Success, `1` = Findings, `2` = User Error, `3` = System Error).
