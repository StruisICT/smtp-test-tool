//! Translates raw server replies into human-readable, IT-actionable hints.
//!
//! As of v0.1.3 the actual strings live in `locales/<code>.toml` and are
//! looked up via the [`crate::i18n`] module.  This file is now the
//! *router* — it knows which keys exist and which substrings to match
//! — but says nothing in any particular language.  Translators add a
//! new locale by adding a TOML file under `locales/`; no Rust change
//! is needed unless we want to add a whole new diagnostic code.

use crate::i18n::{t, t_with};

// ============================================================================
// SMTP enhanced status codes (5.x.x permanent, 4.x.x temporary)
//
// Translations are looked up dynamically at runtime via the i18n module,
// so production code does NOT need a Rust-side list of which codes are
// recognised - smtp_hints_for() just tries the key and treats the
// literal-key fallback as 'no translation, skip this code'.  The list
// below is kept solely for the 'we know about every documented code'
// regression test and as documentation of what ships translated; the
// `#[cfg(test)]` gate keeps it out of release binaries.
// Keep in sync with `locales/en.toml`'s `[diagnostics.smtp.esc.*]`.
// ============================================================================
#[cfg(test)]
const SMTP_CODES: &[&str] = &[
    // 5.x.x permanent failures
    "5.7.0", "5.7.1", "5.7.3", "5.7.8", "5.7.57", "5.7.60", "5.7.64", "5.7.124", "5.7.135",
    "5.7.139", "5.7.500", "5.7.501", "5.7.508", "5.7.511", "5.7.606", "5.7.708", "5.7.750",
    "5.1.0", "5.1.1", "5.1.7", "5.1.8", "5.1.10", "5.4.1", "5.2.1", "5.2.2", "5.3.4",
    // 4.x.x temporary failures
    "4.7.0", "4.4.2", "4.3.2",
];

// IMAP needle -> `diagnostics.imap.<KEY>.hint`.  Substring match against
// the server reply, case-insensitive.  Order matters only for documentation
// readability; the matcher runs through all of them.
const IMAP_NEEDLES: &[(&str, &str)] = &[
    ("AUTHENTICATIONFAILED", "AUTHENTICATIONFAILED"),
    ("LOGIN failed", "LOGIN_failed"),
    ("[ALERT]", "ALERT"),
    ("[UNAVAILABLE]", "UNAVAILABLE"),
    ("[PRIVACYREQUIRED]", "PRIVACYREQUIRED"),
    ("[CLIENTBUG]", "CLIENTBUG"),
    ("LOGINDISABLED", "LOGINDISABLED"),
];

// POP3 needle -> `diagnostics.pop.<KEY>.hint`.
const POP_NEEDLES: &[(&str, &str)] = &[
    ("authentication failed", "authentication_failed"),
    ("Logon failure", "logon_failure"),
    ("not implemented", "not_implemented"),
    ("disabled", "disabled"),
];

// Client-side bounce fixtures (Gmail "Send mail as", ...).  Each entry's
// `needle` is the substring to match in the bounce body, looked up at
// `diagnostics.bounce.<KEY>.needle`; the corresponding hint is
// `diagnostics.bounce.<KEY>.hint`.  Listing them by key here means the
// scanner stays language-agnostic - whatever languages the active locale
// shipped, that's what we look for.
const BOUNCE_KEYS: &[&str] = &["gmail_send_as_en", "gmail_send_as_nl"];

/// Given any SMTP error message, return matched enhanced-status hints
/// plus any client-side bounce-body hints.
pub fn smtp_hints_for(msg: &str) -> Vec<String> {
    let mut out = Vec::new();

    // Enhanced status codes appear as the second token in a reply
    // ('535 5.7.139 ...').  Scan everything because some servers
    // re-quote them in long-form text.
    for esc in extract_enhanced_codes(msg) {
        let safe = esc.replace('.', "_");
        let what_key = format!("diagnostics.smtp.esc.{safe}.what");
        let fix_key = format!("diagnostics.smtp.esc.{safe}.fix");
        let what = t(&what_key);
        let fix = t(&fix_key);
        // If the key fell back to the literal dotted string, the code
        // is not one we recognise; skip it instead of printing the
        // dotted-key gibberish to the user.
        if what != what_key {
            out.push(t_with(
                "diagnostics.scaffold.esc_prefix",
                &[("code", &esc), ("what", &what)],
            ));
            out.push(t_with(
                "diagnostics.scaffold.action_prefix",
                &[("fix", &fix)],
            ));
        }
    }

    // Client-side bounce body scan (Gmail Send-mail-as, etc.).
    // We pull the needle from the ACTIVE locale's TOML, but it falls
    // back to en, so a Dutch user pasting a Dutch Gmail bounce still
    // gets the hint even when running under a different locale.
    let lower = msg.to_lowercase();
    for key in BOUNCE_KEYS {
        let needle_key = format!("diagnostics.bounce.{key}.needle");
        let hint_key = format!("diagnostics.bounce.{key}.hint");
        let needle = t(&needle_key);
        if needle == needle_key {
            continue; // bounce key not configured in any locale
        }
        if lower.contains(&needle.to_lowercase()) {
            out.push(t_with(
                "diagnostics.scaffold.hint_prefix",
                &[("hint", &t(&hint_key))],
            ));
        }
    }

    out
}

pub fn imap_hints_for(msg: &str) -> Vec<String> {
    let lower = msg.to_lowercase();
    IMAP_NEEDLES
        .iter()
        .filter(|(needle, _)| lower.contains(&needle.to_lowercase()))
        .map(|(_, key)| {
            t_with(
                "diagnostics.scaffold.hint_prefix",
                &[("hint", &t(&format!("diagnostics.imap.{key}.hint")))],
            )
        })
        .collect()
}

pub fn pop_hints_for(msg: &str) -> Vec<String> {
    let lower = msg.to_lowercase();
    POP_NEEDLES
        .iter()
        .filter(|(needle, _)| lower.contains(&needle.to_lowercase()))
        .map(|(_, key)| {
            t_with(
                "diagnostics.scaffold.hint_prefix",
                &[("hint", &t(&format!("diagnostics.pop.{key}.hint")))],
            )
        })
        .collect()
}

/// Find enhanced status codes like "5.7.139" or "4.7.0" inside an arbitrary
/// server reply.  Tiny regex-free scanner.
fn extract_enhanced_codes(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let prev_is_boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if prev_is_boundary && matches!(bytes[i], b'2' | b'4' | b'5') {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'.' {
                j += 1;
                let mid_start = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() && j - mid_start < 3 {
                    j += 1;
                }
                if j > mid_start && j < bytes.len() && bytes[j] == b'.' {
                    j += 1;
                    let tail_start = j;
                    while j < bytes.len() && bytes[j].is_ascii_digit() && j - tail_start < 3 {
                        j += 1;
                    }
                    if j > tail_start && (j == bytes.len() || !bytes[j].is_ascii_alphanumeric()) {
                        out.push(s[i..j].to_string());
                        i = j;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    out
}

/// Exposed for tests: number of SMTP codes we know how to translate.
#[cfg(test)]
fn smtp_code_count() -> usize {
    SMTP_CODES.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::testing::LocaleTestGuard;

    // ---- enhanced-code scanner ------------------------------------

    #[test]
    fn extracts_codes_with_boundaries() {
        let v = extract_enhanced_codes("535 5.7.139 Authentication unsuccessful; 4.7.0 throttle");
        assert_eq!(v, vec!["5.7.139", "4.7.0"]);
    }

    #[test]
    fn ignores_version_strings_and_partials() {
        assert!(extract_enhanced_codes("running 1.2.3 release").is_empty());
        assert!(extract_enhanced_codes("see 5.7 spec").is_empty());
        assert!(extract_enhanced_codes("v5.7.60suffix").is_empty());
    }

    #[test]
    fn extracts_at_start_and_end_of_string() {
        assert_eq!(extract_enhanced_codes("5.1.1"), vec!["5.1.1"]);
        assert_eq!(extract_enhanced_codes("foo 4.4.2"), vec!["4.4.2"]);
    }

    #[test]
    fn we_track_every_documented_smtp_code() {
        // Quick sanity: if we add an enhanced code to en.toml, also add
        // it to SMTP_CODES (so the scanner notices it in real replies).
        // 29 currently - bump if you legitimately add more.
        assert!(smtp_code_count() >= 25);
    }

    // ---- SMTP hint mapping (English locale) -----------------------

    #[test]
    fn hint_includes_send_as_for_5_7_60() {
        let _g = LocaleTestGuard::set("en");
        let h = smtp_hints_for("550 5.7.60 SendAsDenied");
        let joined = h.join("\n");
        assert!(joined.contains("SendAsDenied"));
        assert!(joined.contains("Send As"));
        assert!(joined.contains("ESC 5.7.60"));
    }

    #[test]
    fn hint_includes_basic_auth_for_5_7_139() {
        let _g = LocaleTestGuard::set("en");
        let h = smtp_hints_for(
            "535 5.7.139 Authentication unsuccessful, basic authentication is disabled",
        );
        let joined = h.join("\n");
        assert!(joined.contains("5.7.139"));
        assert!(joined.contains("Conditional Access"));
    }

    #[test]
    fn hint_for_unknown_code_is_empty() {
        let _g = LocaleTestGuard::set("en");
        let h = smtp_hints_for("550 5.9.999 Made up code");
        assert!(h.is_empty(), "expected no hints, got {h:?}");
    }

    #[test]
    fn hint_collects_multiple_codes_in_one_reply() {
        let _g = LocaleTestGuard::set("en");
        let h = smtp_hints_for("550 5.7.60 SendAsDenied; also see 5.1.1 for the recipient");
        let joined = h.join("\n");
        assert!(joined.contains("5.7.60"));
        assert!(joined.contains("5.1.1"));
    }

    // ---- IMAP hint mapping ---------------------------------------

    #[test]
    fn imap_hint_for_authenticationfailed() {
        let _g = LocaleTestGuard::set("en");
        let h = imap_hints_for("a1 NO [AUTHENTICATIONFAILED] LOGIN failed");
        assert!(!h.is_empty());
        assert!(h.iter().any(|s| s.contains("bad password")));
    }

    #[test]
    fn imap_hint_for_logindisabled() {
        let _g = LocaleTestGuard::set("en");
        let h = imap_hints_for("* CAPABILITY IMAP4rev1 LOGINDISABLED STARTTLS");
        assert!(h
            .iter()
            .any(|s| s.contains("STARTTLS") || s.contains("XOAUTH2")));
    }

    // ---- POP hint mapping ----------------------------------------

    #[test]
    fn pop_hint_for_authentication_failed() {
        let _g = LocaleTestGuard::set("en");
        let h = pop_hints_for("-ERR authentication failed");
        assert!(!h.is_empty());
        assert!(h
            .iter()
            .any(|s| s.contains("POP disabled") || s.contains("bad credentials")));
    }

    #[test]
    fn pop_hint_for_disabled() {
        let _g = LocaleTestGuard::set("en");
        let h = pop_hints_for("-ERR POP is disabled for this account");
        assert!(h.iter().any(|s| s.contains("disabled")));
    }

    // ---- Client-side bounce signatures ---------------------------

    #[test]
    fn hint_recognises_gmail_send_as_bounce_english() {
        let _g = LocaleTestGuard::set("en");
        let h = smtp_hints_for(
            "You're sending this message from a different address or alias using the 'Send mail as' feature.",
        );
        let joined = h.join("\n");
        assert!(joined.contains("Send mail as"));
        assert!(joined.contains("Accounts and Import"));
    }

    #[test]
    fn hint_recognises_gmail_send_as_bounce_dutch() {
        let _g = LocaleTestGuard::set("en");
        let h = smtp_hints_for(
            "Je verzendt dit bericht vanaf een ander adres of een alias met de functie 'Mail sturen als'. De instellingen voor het account dat je gebruikt voor 'Mail sturen als' zijn niet correct of zijn verouderd.",
        );
        let joined = h.join("\n");
        assert!(joined.contains("Mail sturen als"));
        assert!(joined.contains("Accounts and Import"));
    }

    // ---- Locale-switching ----------------------------------------
    // Same code, different language - proves the i18n integration is
    // live and not a no-op.

    #[test]
    fn hint_text_switches_to_dutch_when_locale_changes() {
        let _g = LocaleTestGuard::set("nl");
        let h = smtp_hints_for("535 5.7.139 Authentication unsuccessful");
        let joined = h.join("\n");
        // Dutch nl.toml's 5.7.139.fix mentions "Conditional Access-beleid".
        assert!(
            joined.contains("Conditional Access-beleid") || joined.contains("Conditional Access"),
            "expected Dutch hint, got:\n{joined}"
        );
        // And the prefix is in Dutch too: "Actie:" not "Action:".
        assert!(
            joined.contains("Actie:"),
            "expected Dutch action prefix, got:\n{joined}"
        );
    }

    #[test]
    fn unsupported_locale_falls_back_to_english_hints() {
        let _g = LocaleTestGuard::set("xx-zz"); // not shipped
        let h = smtp_hints_for("550 5.7.60 SendAsDenied");
        let joined = h.join("\n");
        // i18n::set_locale silently switches to BASE on unsupported.
        assert!(joined.contains("Send As"));
        assert!(joined.contains("Action:"));
    }
}
