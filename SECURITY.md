# Security Policy

`smtp-test-tool` is a diagnostic tool that handles live mail-server
credentials, so we take its security posture seriously.

## Supported versions

This project is pre-1.0 and ships from a single `main` line. Security
fixes land on `main` and in the **latest tagged release** only. There
are no long-term-support branches for older `0.x` tags — please upgrade
to the newest release before reporting.

| Version            | Supported            |
| ------------------ | -------------------- |
| Latest release     | ✅                   |
| Any older `0.x`    | ❌ (upgrade first)   |

## How credentials are handled (by design)

Understanding this helps when judging whether something is a
vulnerability:

- Passwords and OAuth tokens are **never** written to the config file
  (`smtp_test_tool.toml`), the logs, or eframe/egui persistence. This
  is enforced at the type level via `#[serde(skip)]` on
  `Profile::password` / `::oauth_token` and by a regression test
  (`tests/config_roundtrip.rs`).
- The **only** approved persistent store is the OS keychain
  (`src/keystore.rs`): Windows Credential Manager, macOS Keychain, or
  Linux Secret Service. It provides real at-rest encryption gated by
  the OS login/unlock prompt.
- All transport uses `rustls` (no OpenSSL on the host). CA trust comes
  from `webpki-roots` plus any user-supplied `ca_file`.

A report that credentials reach a TOML file, a log sink, or any
plaintext on-disk store would be a genuine, high-priority issue.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Use GitHub's private reporting instead:

1. Go to the repository's **Security** tab →
   **Report a vulnerability** (GitHub Private Vulnerability Reporting).
2. Or, if that is unavailable, open a private
   [security advisory](https://github.com/StruisICT/smtp-test-tool/security/advisories/new).

Please include:

- The version (`smtp-test-tool --version`) and OS.
- A description of the issue and its impact.
- Steps to reproduce, ideally with a minimal config (redact real
  credentials).

### What to expect

- **Acknowledgement:** within 7 days.
- **Assessment + plan:** within 14 days of acknowledgement.
- **Fix + disclosure:** coordinated with you; we credit reporters in
  the `CHANGELOG.md` entry unless you ask us not to.

This is a small, volunteer-maintained project — timelines are
best-effort, but we will keep you informed.
