# AGENTS.md — Working agreement for AI coding agents on this repo

> **Loaded automatically by Claude Code, Cursor, Aider, and most other
> agent harnesses.** Every contributor (human or AI) MUST read this file
> before changing code. Violations are merge-blockers.

---

## 1. Ground rules (hard requirements)

1. **Quality over quantity.** One feature done well beats three half-baked
   features. If you cannot finish something to the standard below in the
   current session, leave it out and open a tracking issue instead.

2. **Verify "latest" against live sources.** Before adding or upgrading any
   dependency, language version, GitHub Action, or framework, confirm the
   current stable release from an authoritative source:
   - Rust crates: `cargo search <crate> --limit 1` or
     `curl -s https://crates.io/api/v1/crates/<crate> | jq -r .crate.max_stable_version`
   - GitHub Actions: check the action's repo `Releases` page (or
     `gh release view --repo owner/repo --json tagName`).
   - Rust toolchain: `https://forge.rust-lang.org/infra/channel-layout.html`
     or `rustup check`.
   - Do **not** trust prior agent memory for version numbers.

3. **Accessibility is the bare minimum, not a stretch goal.** Every UI
   surface (desktop GUI, web pages, generated docs site, CLI output) MUST
   meet **WCAG 2.2 Level AAA** at a minimum:
   - Text contrast ≥ 7:1 against its background (≥ 4.5:1 for large text).
   - All information conveyed by colour MUST also have a textual cue
     (`[PASS]`, `[FAIL]`, icons with labels, etc.). Colour is never the
     only signal.
   - Full keyboard operability with a visible focus indicator.
   - No content flashes more than 3× per second.
   - Form fields have visible, programmatic labels (not placeholder-only).
   - Live regions / status messages announced to assistive tech (egui ⇒
     AccessKit, web ⇒ `aria-live`).
   - Honour `prefers-reduced-motion` and `prefers-contrast`.

4. **Dark + light mode, on every OS, always.** Every UI MUST detect and
   follow the operating-system appearance setting (Windows registry,
   macOS `AppleInterfaceStyle`, GNOME/KDE/Cosmic, web
   `prefers-color-scheme`). A manual override MUST also be available, and
   the chosen theme MUST persist between sessions.

5. **No shortcuts, even if they look like overkill.** Hand-rolled JSON
   parser when serde exists? No. Single-file 3000-line module to "save
   time"? No. The right tool, modular code, real tests, real error
   handling. If a solution feels too clever, it is wrong.

6. **Commit early, commit often, atomic commits.** Every logically
   independent change is its own commit with a [Conventional Commits]
   message (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`,
   `ci:`, `perf:`). Never bundle unrelated changes. This is what lets us
   `git revert` cleanly when something breaks. Push to a feature branch,
   open a PR, let CI run; merge only when green.

7. **Polish counts.** GUI spacing, web typography, CLI output alignment,
   error message wording — all of it is part of the product. If it looks
   amateur, it is broken.

8. **Credentials never touch the config file, logs, or eframe state.**
   Passwords, OAuth bearer tokens, API keys, and similar secrets live
   in process memory for the current session only — OR in an OS
   keychain via `src/keystore.rs`, which is the **one** approved
   persistent store. The OS keychain provides real at-rest encryption
   gated by the OS login / unlock prompt; our own TOML files do not.
   Enforced at the type level via `#[serde(skip)]` on
   `Profile::password` and `::oauth_token`, behaviourally by
   `tests/config_roundtrip.rs::save_never_writes_credentials_even_when_set`,
   and the keychain code itself is feature-gated so a CLI-only build
   can ship without ever linking the keyring crate. Removing or
   weakening any of those is a merge blocker.

[Conventional Commits]: https://www.conventionalcommits.org/

---

## 2. Stack of record (so agents don't churn it)

| Layer            | Choice                | Why                                            |
| ---------------- | --------------------- | ---------------------------------------------- |
| Language         | Rust (edition 2021)   | Safety, single static binary, modern tooling.  |
| MSRV             | 1.92                  | Floor set by the egui 0.34 ecosystem.          |
| TLS              | `rustls` + ring       | Pure Rust, no OpenSSL on host.                 |
| SMTP             | `lettre` 0.11+        | De-facto Rust SMTP client.                     |
| IMAP / POP3      | hand-rolled on rustls | Owns the wire trace for diagnostics.           |
| CLI parsing      | `clap` 4 derive       | Standard.                                      |
| Config           | `serde` + `toml`      | Human-editable, IT-friendly.                   |
| Logging          | `tracing` family      | One subscriber, many sinks (CLI, GUI, file).   |
| Desktop GUI      | `eframe`/`egui`       | Single binary, AccessKit, OS theme follow.     |
| Web (if needed)  | not yet decided       | When added: must meet rule #3 from day one.    |

Before changing any of the above, open an issue with rationale; never
silently swap.

---

## 3. Definition of Done for any change

A pull request is **only** ready to merge when **all** of these are true:

- [ ] Builds clean on Linux + macOS + Windows in CI.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes.
- [ ] `cargo test --all-features` passes.
- [ ] `cargo deny check` passes (advisories, licenses, sources, bans).
- [ ] If user-facing: screenshots in dark **and** light mode attached to
      the PR, plus a paragraph describing the keyboard path through the
      new UI.
- [ ] If protocol-affecting: example real-world server diagnostic added
      to `tests/diagnostics.rs`.
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`.
- [ ] No `unwrap()` / `expect()` in non-test code without a
      `// SAFETY:`-style comment justifying it.
- [ ] No new dependency added without verifying it is the latest stable
      (rule #2) and that `cargo deny` accepts its licence.

---

## 4. Commit / branch workflow

```
main          ← protected, always green, always shippable
└── feat/x    ← short-lived branches, squash-merge via PR
```

- One PR = one concern.
- Commit message body explains *why*, not *what* (the diff shows what).
- Reference issues with `Refs #N` or `Closes #N`.
- Tag releases with `vX.Y.Z`; CI then builds and publishes binaries +
  the crate to crates.io.

---

## 5. When you (an AI agent) are blocked

- Do not invent API surfaces. Read the actual crate docs (`cargo doc
  --open` or docs.rs) before guessing.
- If a build fails, paste the **exact** error in your reply and fix
  the smallest possible thing first — do not refactor under cover of a
  bug fix.
- If you broke something, `git status` and `git diff` before doing
  anything else. If unsure, `git stash` and ask the user.
- Tell the user the truth, including "I can't verify X right now
  because Y". Do not bluff.

---

## 6. Versioning (SemVer 2.0.0)

This project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html)
to the letter. Versions are `MAJOR.MINOR.PATCH`, optionally with a
`-prerelease` and/or `+build` suffix. `Cargo.toml` is the single
source of truth for the number; the git tag is the same value with a
`v` prefix (`vX.Y.Z`).

### What counts as the public API

A change is **breaking** if it breaks any of these contracts for an
existing user:

1. **Library surface** — anything reachable from `smtp_test_tool::`
   (the `pub` items re-exported in `src/lib.rs`): types, fields,
   function signatures, enum variants, trait impls, and the set of
   Cargo feature names.
2. **CLI contract** — subcommand names, flag/argument names and their
   meaning, and the documented exit codes (`0` pass, `1` fail,
   `2` config/internal error).
3. **Config + persistence schema** — the TOML keys in
   `smtp_test_tool.toml` and their semantics, plus the OS-keychain
   entry naming.

Internal modules, private items, log wording, and the exact text of
diagnostic hints are **not** part of the public API and may change in
any release.

### Choosing the bump

- **MAJOR** — remove or rename a public item, change a function
  signature or a CLI flag, change an exit code, drop a config key, or
  any other backward-incompatible change.
- **MINOR** — add a public item, CLI subcommand/flag, config key,
  protocol, provider preset, locale, or Cargo feature in a
  backward-compatible way (also: mark something deprecated without
  removing it).
- **PATCH** — a backward-compatible bug fix only; no new public
  surface.

### 0.y.z (we are here)

While the version is `0.y.z` the public API is **not** stable
(spec §4). Our self-imposed discipline during 0.x:

- A breaking change bumps the **MINOR**: `0.2.x` → `0.3.0`.
- A backward-compatible feature or fix bumps the **PATCH**:
  `0.2.0` → `0.2.1`.
- `1.0.0` is the first release that *commits* to a stable API. Do
  not cut it until the library surface, CLI, and config schema are
  ones we are willing to keep stable.

### Pre-releases and build metadata

- Pre-release identifiers (`1.0.0-rc.1`, `0.3.0-beta.2`) are
  dot-separated alphanumerics and rank **below** the matching
  release. A tag containing a `-` is published as a GitHub
  *prerelease* automatically (`release.yml`).
- Build metadata (`+…`) is permitted by the spec but we do not use
  it; it is ignored for precedence.
- **MSRV is orthogonal to SemVer.** Raising the Rust floor (now
  1.92) is recorded in the CHANGELOG and, for the published library,
  treated as **at least a MINOR** bump.

### Release procedure

1. Pick the bump using the rules above.
2. Edit `version` in `Cargo.toml`; run `cargo build` so `Cargo.lock`
   updates its own package entry too.
3. In `CHANGELOG.md`, rename `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD` and open a fresh empty `## [Unreleased]`
   above it.
4. Commit `chore(release): bump to X.Y.Z`.
5. `git tag -a vX.Y.Z -m "vX.Y.Z"` and push the tag. CI gates the
   release on tag == `Cargo.toml` == a matching `CHANGELOG` section,
   then builds binaries, publishes, and refreshes the package
   manifests.

---

## 7. Current state & resume context

> Snapshot for whoever (human or AI) picks this up next — on a fresh
> PC, a different tool, or weeks later. **Keep this section current:**
> when you ship something here, update the "Shipped" list, bump the
> version note, and re-prioritise "Next up" before you finish a
> session. Treat a stale snapshot here as a bug.

### Where things live

- **Repo / org:** `github.com/StruisICT/smtp-test-tool` (moved from
  `Struis112`; old URLs redirect for ~12 months).
- **Crate:** `smtp-test-tool` on crates.io (lib name `smtp_test_tool`).
- **Binaries:** `smtp-test-tool` (CLI) + `smtp-test-tool-gui` (GUI,
  `gui` feature). Single static binary per OS, no host OpenSSL.
- **Package channels:** WinGet (`StruisICT.SmtpTestTool`), Scoop
  (`struisict` bucket), Homebrew (`struisict/tap`). Manifests in
  `packaging/`, auto-refreshed by `.github/workflows/release.yml`.
- **Default features:** `gui`, `keychain`, `dns`, `oauth`.

### Shipped (as of v0.2.0)

- SMTP (lettre) + hand-rolled IMAP / POP3 over rustls, full wire trace.
- IT-actionable diagnostics (M365 error-code translation).
- 11 provider presets; TOML profiles; OS-keychain credential storage.
- DNS audit (MX / SPF / DMARC + hints), CLI `dns` + GUI **DNS check**.
- M365 OAuth2 device-code flow (RFC 8628), CLI `oauth-login` + GUI.
- 36 locales / 11 scripts, OS dark/light follow, WCAG 2.2 AAA, AccessKit.

### In flight (`## [Unreleased]` in CHANGELOG.md)

- Org/brand migration `Struis112` → `StruisICT` (repo, Scoop bucket,
  Homebrew tap). The WinGet PR was **withdrawn** during the move and
  needs re-submitting under the `StruisICT` publisher.

### Next up (suggested order — confirm with the maintainer)

1. Cut a release for the migration changes (bump version, tag, let CI
   publish), then re-submit the WinGet PR (`packaging/README.md` has
   the recipe).
2. New diagnostic: DKIM record lookup/validation (natural companion to
   the existing SPF/DMARC audit in `src/dns.rs`); then MTA-STS /
   TLS-RPT / BIMI as follow-ups.

### Verify-green checklist (run before any commit)

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test  --all-features
cargo deny  check
```

GUI screenshots regenerate via `tools/` (see `tools/README.md`) and
must be attached for any user-facing change, in **both** themes.
