# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Manual theme override on the GUI Advanced tab.**  Auto / Dark /
  Light, with the resolved OS hint shown next to the Auto label;
  persisted through `Profile.theme` so existing v0.1.0 configs keep
  working without a migration.
- Dark + light GUI screenshots in `docs/screenshots/`, regenerable
  on Windows via `tools/screenshot.ps1`.  Linked from the README.
- 14 additional tests (now 17 total, was 3): full diagnostic
  translator coverage (SMTP enhanced-code boundaries, IMAP
  AUTHENTICATIONFAILED / LOGINDISABLED, POP -ERR phrases) plus a new
  integration test suite at `tests/config_roundtrip.rs` covering
  save+load symmetry, opt-in password obfuscation, multi-profile,
  and defaults-fallback for minimal hand-written configs.

### Fixed
- **Default config filename was still `email_tester.toml`** after the
  project rename, so `discover_config_path()` never found the file
  every doc told the user to create.  The GUI showed 'no config
  file' even with a valid TOML next to the exe; the CLI silently
  fell back to built-in Outlook defaults.
- GUI Servers tab body rendered empty due to a nested-ScrollArea
  height race in the egui 0.34 layout.  Split the log into its own
  resizable BottomPanel; tabs now get a properly-sized CentralPanel.
- GUI log panel was drowning in eframe / winit / glow / wgpu DEBUG
  noise.  Default tracing filter is now `info,eframe=warn,...`;
  power users can opt into more verbose output via `RUST_LOG`.
- `Config::load` parse errors are no longer silently swallowed; the
  GUI now logs the path and error so users can tell 'no config' from
  'config exists but won't parse'.

### Changed
- `cargo deny` `multiple-versions` ratcheted from `warn` to `deny`.
  The 20 known duplicate transitives are enumerated in `deny.toml`
  with a `reason` field each; any NEW duplicate will fail CI.

## [0.1.0] - 2026-05-19

### Added
- Initial Rust port of the email connectivity tester.
- CLI binary (`smtp-test-tool`) with TOML config + named profiles and
  Outlook.com defaults.
- GUI binary (`smtp-test-tool-gui`) built on eframe/egui with OS
  dark/light auto-follow (hand-rolled detection, no third-party crate)
  and AccessKit screen-reader support.
- IT-actionable diagnostic translator for the most common Microsoft
  365 SMTP failure codes (5.7.60 SendAsDenied, 5.7.139 Basic-Auth-
  disabled, 5.7.57 unauthenticated MAIL FROM, …).
- Hand-rolled IMAP + POP3 clients over `rustls` so we own the full
  wire trace.
- Public release infrastructure: GitHub Actions CI matrix (fmt,
  clippy, test on Linux/macOS/Windows, MSRV 1.92, cargo-deny,
  cargo-llvm-cov → Codecov, cargo doc → GitHub Pages); release
  workflow producing cross-OS binaries on tag push and publishing
  to crates.io.

### Project conventions
- `AGENTS.md` captures the working agreement: WCAG 2.2 AAA is the
  baseline, dark+light mode on every OS is mandatory, atomic
  conventional commits, no shortcuts.

[Unreleased]: https://github.com/Struis112/smtp-test-tool/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Struis112/smtp-test-tool/releases/tag/v0.1.0
