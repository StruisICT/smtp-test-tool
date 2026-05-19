//! Built-in mail-provider presets.
//!
//! Selecting a preset overwrites the SMTP / IMAP / POP3 host, port, and
//! security fields on the active profile - nothing else.  Credentials,
//! the chosen profile name, theme, and other settings are left alone.
//!
//! The list is deliberately small and curated.  When you have to add an
//! eleventh entry, ask whether one of the existing ten can go first.
//!
//! Sources verified against each provider's official documentation at
//! the time of writing; ports/hosts are stable across years for these
//! services.  If a value rots, users can always pick "Custom" and edit
//! the host field directly.

use crate::tls::Security;

/// One protocol endpoint (SMTP / IMAP / POP3).
#[derive(Debug, Clone, Copy)]
pub struct ServerSpec {
    pub host: &'static str,
    pub port: u16,
    pub security: Security,
}

/// A named bundle of endpoints for one mail provider.
#[derive(Debug, Clone, Copy)]
pub struct Provider {
    /// Human-readable name shown in the UI dropdown.
    pub name: &'static str,
    /// Optional clarification shown under the dropdown - app-password
    /// requirements, "needs Proton Bridge running", etc.
    pub note: Option<&'static str>,
    pub smtp: ServerSpec,
    pub imap: ServerSpec,
    /// Some providers do not expose POP3 at all (iCloud, Proton Bridge,
    /// Microsoft 365 work mailboxes in many tenants).  `None` means
    /// "leave the POP3 fields alone and disable the POP3 test by default".
    pub pop: Option<ServerSpec>,
}

/// Standard submission + secure-access ports.
const STARTTLS: Security = Security::StartTls;
const SSL: Security = Security::Implicit;

/// The ten built-in providers, in roughly descending popularity, plus a
/// note about Proton Bridge because it's the most surprising entry.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "Outlook.com / Hotmail (consumer)",
        note: None,
        smtp: ServerSpec { host: "smtp-mail.outlook.com",   port: 587, security: STARTTLS },
        imap: ServerSpec { host: "outlook.office365.com",   port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "outlook.office365.com", port: 995, security: SSL }),
    },
    Provider {
        name: "Microsoft 365 / Office 365 (work)",
        note: Some("Tenant may have SMTP AUTH disabled - see the 5.7.139 hint."),
        smtp: ServerSpec { host: "smtp.office365.com",      port: 587, security: STARTTLS },
        imap: ServerSpec { host: "outlook.office365.com",   port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "outlook.office365.com", port: 995, security: SSL }),
    },
    Provider {
        name: "Gmail / Google Workspace",
        note: Some("Requires a Google App Password if 2-Step Verification is on."),
        smtp: ServerSpec { host: "smtp.gmail.com",          port: 587, security: STARTTLS },
        imap: ServerSpec { host: "imap.gmail.com",          port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "pop.gmail.com",      port: 995, security: SSL }),
    },
    Provider {
        name: "Yahoo Mail",
        note: Some("Generate an App Password at account-security; the regular password is rejected."),
        smtp: ServerSpec { host: "smtp.mail.yahoo.com",     port: 587, security: STARTTLS },
        imap: ServerSpec { host: "imap.mail.yahoo.com",     port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "pop.mail.yahoo.com", port: 995, security: SSL }),
    },
    Provider {
        name: "iCloud / Apple Mail",
        note: Some("Use an app-specific password from appleid.apple.com (2FA is required)."),
        smtp: ServerSpec { host: "smtp.mail.me.com",        port: 587, security: STARTTLS },
        imap: ServerSpec { host: "imap.mail.me.com",        port: 993, security: SSL },
        pop:  None,
    },
    Provider {
        name: "Proton Mail (Bridge)",
        note: Some("Requires Proton Bridge running locally; password is the Bridge-generated one, not your Proton account password."),
        smtp: ServerSpec { host: "127.0.0.1",               port: 1025, security: STARTTLS },
        imap: ServerSpec { host: "127.0.0.1",               port: 1143, security: STARTTLS },
        pop:  None,
    },
    Provider {
        name: "Fastmail",
        note: Some("Generate an App Password under Settings > Privacy & Security."),
        smtp: ServerSpec { host: "smtp.fastmail.com",       port: 587, security: STARTTLS },
        imap: ServerSpec { host: "imap.fastmail.com",       port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "pop.fastmail.com",   port: 995, security: SSL }),
    },
    Provider {
        name: "Zoho Mail",
        note: None,
        smtp: ServerSpec { host: "smtp.zoho.com",           port: 587, security: STARTTLS },
        imap: ServerSpec { host: "imap.zoho.com",           port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "pop.zoho.com",       port: 995, security: SSL }),
    },
    Provider {
        name: "AOL Mail",
        note: Some("Requires an App Password if 2-step verification is on."),
        smtp: ServerSpec { host: "smtp.aol.com",            port: 587, security: STARTTLS },
        imap: ServerSpec { host: "imap.aol.com",            port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "pop.aol.com",        port: 995, security: SSL }),
    },
    Provider {
        name: "GMX / Mail.com",
        note: None,
        smtp: ServerSpec { host: "mail.gmx.com",            port: 587, security: STARTTLS },
        imap: ServerSpec { host: "imap.gmx.com",            port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "pop.gmx.com",        port: 995, security: SSL }),
    },
    Provider {
        name: "Yandex Mail",
        note: None,
        smtp: ServerSpec { host: "smtp.yandex.com",         port: 465, security: SSL },
        imap: ServerSpec { host: "imap.yandex.com",         port: 993, security: SSL },
        pop:  Some(ServerSpec { host: "pop.yandex.com",     port: 995, security: SSL }),
    },
];

/// Find a provider by exact name match (case-sensitive).
pub fn by_name(name: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.name == name)
}

/// Best-effort reverse lookup: which provider does the current Profile
/// resemble?  Returns `Some(provider)` when ALL three protocol hosts
/// match exactly, else `None` (meaning the user has a custom setup).
pub fn detect(smtp_host: &str, imap_host: &str, pop_host: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| {
        p.smtp.host == smtp_host
            && p.imap.host == imap_host
            && p.pop.map(|s| s.host).unwrap_or(pop_host) == pop_host
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique() {
        // A duplicate name would silently make by_name() return the
        // first match while the dropdown shows two entries - both are
        // user-hostile.
        let mut seen = std::collections::HashSet::new();
        for p in PROVIDERS {
            assert!(seen.insert(p.name), "duplicate provider name: {}", p.name);
        }
    }

    #[test]
    fn outlook_consumer_is_first_for_back_compat() {
        // v0.1.0 shipped Outlook.com defaults; the first entry of the
        // list is the default fallback if a config has no provider hint.
        assert_eq!(
            PROVIDERS.first().map(|p| p.name),
            Some("Outlook.com / Hotmail (consumer)")
        );
    }

    #[test]
    fn every_provider_has_smtp_and_imap() {
        for p in PROVIDERS {
            assert!(!p.smtp.host.is_empty(), "{} has empty smtp.host", p.name);
            assert!(p.smtp.port > 0, "{} has invalid smtp.port", p.name);
            assert!(!p.imap.host.is_empty(), "{} has empty imap.host", p.name);
            assert!(p.imap.port > 0, "{} has invalid imap.port", p.name);
        }
    }

    #[test]
    fn by_name_round_trip() {
        for p in PROVIDERS {
            let back = by_name(p.name).expect("known provider");
            assert_eq!(back.smtp.host, p.smtp.host);
        }
        assert!(by_name("definitely not a real provider").is_none());
    }

    #[test]
    fn detect_finds_outlook_defaults() {
        let p = detect(
            "smtp-mail.outlook.com",
            "outlook.office365.com",
            "outlook.office365.com",
        );
        assert_eq!(p.map(|p| p.name), Some("Outlook.com / Hotmail (consumer)"));
    }

    #[test]
    fn detect_returns_none_for_custom_setup() {
        assert!(detect(
            "smtp.example.invalid",
            "imap.example.invalid",
            "pop.example.invalid"
        )
        .is_none());
    }
}
