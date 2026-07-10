//! DNS-side checks for a mail domain.
//!
//! Most mail-flow problems we get blamed for are actually somebody
//! else's DNS: a missing SPF record, a `p=none` DMARC policy that the
//! receiving side has tightened to `p=reject`, a forgotten MX, a weak
//! or revoked DKIM key.  This module runs the apex lookups (MX / SPF /
//! DMARC) plus optional DKIM selector probes that catch ~90% of those
//! failures and turns the raw answers into IT-actionable hints.
//!
//! DKIM is the odd one out: its records live at
//! `<selector>._domainkey.<domain>` and selectors cannot be enumerated
//! from DNS, so the caller must supply them (or lean on
//! [`COMMON_DKIM_SELECTORS`]).  [`audit_domain`] therefore checks the
//! apex records only; [`audit_domain_selectors`] adds DKIM.
//!
//! ## Design
//!
//! The public API is **synchronous** to fit the rest of the codebase
//! (`src/smtp.rs`, `src/imap.rs`, etc.).  Internally we spin up a
//! `tokio` `current_thread` runtime per call because hickory-resolver
//! 0.26 dropped its sync entry points.  The runtime lives for the
//! duration of one `audit_domain` and then drops.
//!
//! No DNSSEC validation, no DoH/DoT - those are valuable but
//! orthogonal additions for a future release.  We use the system
//! resolver configuration (`/etc/resolv.conf` or the Windows
//! equivalent) so the answers match what other tools on the same
//! machine see.

use std::net::IpAddr;
use std::time::Duration;

use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use serde::{Deserialize, Serialize};
use tokio::runtime::Builder;

// =====================================================================
// Public types
// =====================================================================

/// One MX record from the apex domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MxRecord {
    /// Preference / priority value (lower = preferred).
    pub preference: u16,
    /// Exchange hostname (trailing dot stripped).
    pub exchange: String,
    /// Forward A / AAAA addresses for the exchange host, if resolution
    /// succeeded.  Empty vec means we tried and failed - the receiver
    /// will not be able to deliver here.
    pub ips: Vec<IpAddr>,
}

/// SPF record (TXT at the apex starting with `v=spf1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpfRecord {
    /// The full raw `v=spf1 ...` string.
    pub raw: String,
    /// Detected "all" mechanism qualifier:
    ///   - `Some("-")` = `-all`     (fail / hard reject)
    ///   - `Some("~")` = `~all`     (softfail)
    ///   - `Some("?")` = `?all`     (neutral)
    ///   - `Some("+")` = `+all`     (pass anything - effectively no policy)
    ///   - `None`      = no `all` mechanism present
    pub all_qualifier: Option<String>,
}

/// DMARC record (TXT at `_dmarc.<domain>` starting with `v=DMARC1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmarcRecord {
    pub raw: String,
    /// `p=` value: usually `none`, `quarantine`, `reject`.
    pub policy: Option<String>,
    /// `sp=` value (subdomain policy).
    pub subdomain_policy: Option<String>,
    /// `pct=` value (sampling rate).
    pub pct: Option<u8>,
}

/// DKIM public-key record (a TXT record at
/// `<selector>._domainkey.<domain>`, RFC 6376 §3.6.1).
///
/// DKIM is unlike SPF / DMARC in one crucial way: there is **no way to
/// enumerate selectors from DNS** (no wildcard, no listing), so a DKIM
/// lookup is always "does selector *S* exist for this domain?".  The
/// caller supplies the selector(s); [`COMMON_DKIM_SELECTORS`] is a
/// fallback list of names the big platforms publish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimRecord {
    /// The selector queried (the `s1` in `s1._domainkey.example.com`).
    pub selector: String,
    /// Full raw TXT value.
    pub raw: String,
    /// `v=` tag - should be `DKIM1` when present.  It is optional per
    /// RFC 6376 §3.6.1 (most verifiers tolerate its absence) but a
    /// *wrong* value is a red flag.
    pub version: Option<String>,
    /// `k=` key type: `rsa` (the default when the tag is absent) or
    /// `ed25519` (RFC 8463).
    pub key_type: Option<String>,
    /// `p=` public-key data (base64).  `Some("")` is an explicitly
    /// empty key, which per RFC 6376 §3.6.1 means the key has been
    /// **revoked**; `None` means the `p=` tag was missing entirely
    /// (a malformed record).
    pub public_key: Option<String>,
    /// `t=` flag list (colon-separated), e.g. `y` (testing mode) or
    /// `s` (no subdomaining).  Empty when the tag is absent.
    pub flags: Vec<String>,
    /// Key strength in bits, derived from `p=`: the RSA modulus size
    /// for an RSA key we could decode, or 256 for a well-formed
    /// ed25519 key.  `None` for a revoked / empty / undecodable key.
    pub key_bits: Option<u32>,
}

/// Full audit report for one domain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsReport {
    pub domain: String,
    pub mx: Vec<MxRecord>,
    pub spf: Option<SpfRecord>,
    pub dmarc: Option<DmarcRecord>,
    /// DKIM records that were actually found at the probed selectors.
    /// `#[serde(default)]` keeps reports written by older versions
    /// (which had no DKIM field) deserialisable.
    #[serde(default)]
    pub dkim: Vec<DkimRecord>,
    /// Every selector we looked up, whether or not it resolved.  Lets
    /// the renderer say "checked s1, s2 - found none" rather than going
    /// silent, and lets [`interpret`] distinguish "DKIM not probed" from
    /// "probed, nothing there".
    #[serde(default)]
    pub dkim_selectors_checked: Vec<String>,
}

/// Selectors that common mail platforms publish, used as a fallback
/// probe list when the caller does not know the domain's selector.
/// This is a best-effort convenience, **not** an exhaustive list - a
/// domain can use any selector it likes, so "none found here" never
/// proves DKIM is absent.
pub const COMMON_DKIM_SELECTORS: &[&str] = &[
    "selector1",
    "selector2", // Microsoft 365
    "google",    // Google Workspace
    "k1",
    "k2",
    "k3", // Mailchimp / Mandrill, some SendGrid
    "s1",
    "s2",         // generic / SendGrid
    "dkim",       // generic self-hosted
    "default",    // generic self-hosted
    "mail",       // generic self-hosted
    "mandrill",   // Mailchimp transactional
    "amazonses",  // Amazon SES
    "protonmail", // Proton Mail
    "fm1",        // Fastmail
    "zmail",      // Zoho Mail
];

/// One IT-actionable hint produced by `interpret`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHint {
    /// Stable ID for translation lookup, e.g. `"no_mx"`, `"spf_plus_all"`.
    pub id: &'static str,
    /// English fallback text - the GUI can translate via i18n if the
    /// locale has the matching `diagnostics.dns.<id>` key.
    pub text: String,
    /// Severity for UI colouring.
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// "Your mail will be silently dropped" - bright red.
    Critical,
    /// "Your mail looks suspicious; deliverability suffers" - amber.
    Warning,
    /// "Worth knowing but not urgent."
    Info,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("invalid domain name: {0}")]
    BadDomain(String),
    #[error("tokio runtime error: {0}")]
    Runtime(#[from] std::io::Error),
    #[error("resolver error: {0}")]
    Resolver(String),
}

// =====================================================================
// Public entry point
// =====================================================================

/// Run the apex lookups (MX / SPF / DMARC) against `domain` and return
/// a populated report with **no** DKIM probing.  Network-bound; ~1-2s
/// on a healthy network, up to the resolver timeout if DNS is broken.
///
/// DKIM needs a selector, which this signature has no way to supply, so
/// it is left out here to keep the call backward-compatible.  Use
/// [`audit_domain_selectors`] to include DKIM.
pub fn audit_domain(domain: &str) -> Result<DnsReport, DnsError> {
    audit_domain_selectors(domain, &[])
}

/// Like [`audit_domain`], but also probes each of `selectors` for a
/// DKIM record at `<selector>._domainkey.<domain>`.  Pass
/// [`COMMON_DKIM_SELECTORS`] when the domain's real selector is unknown.
/// An empty slice skips DKIM entirely (identical to [`audit_domain`]).
pub fn audit_domain_selectors(domain: &str, selectors: &[&str]) -> Result<DnsReport, DnsError> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    if domain.is_empty() || !domain.contains('.') {
        return Err(DnsError::BadDomain(domain));
    }

    let rt = Builder::new_current_thread().enable_all().build()?;
    rt.block_on(audit_domain_async(&domain, selectors))
}

async fn audit_domain_async(domain: &str, selectors: &[&str]) -> Result<DnsReport, DnsError> {
    // hickory 0.26's builder_tokio reads the system resolver config
    // (/etc/resolv.conf on Unix, the registry on Windows) so our
    // answers match what other tools on the same host see.
    let mut builder =
        TokioResolver::builder_tokio().map_err(|e| DnsError::Resolver(e.to_string()))?;
    builder.options_mut().timeout = Duration::from_secs(5);
    let resolver = builder
        .build()
        .map_err(|e| DnsError::Resolver(e.to_string()))?;

    let mx = lookup_mx(&resolver, domain).await;
    let spf = lookup_spf(&resolver, domain).await;
    let dmarc = lookup_dmarc(&resolver, domain).await;

    // DKIM: one TXT lookup per selector.  Selectors are de-duplicated
    // (case-insensitively) so a caller mixing explicit selectors with
    // the common list doesn't double-probe.
    let mut checked = Vec::new();
    let mut dkim = Vec::new();
    for sel in selectors {
        let sel = sel.trim().to_lowercase();
        if sel.is_empty() || checked.contains(&sel) {
            continue;
        }
        if let Some(rec) = lookup_dkim(&resolver, domain, &sel).await {
            dkim.push(rec);
        }
        checked.push(sel);
    }

    Ok(DnsReport {
        domain: domain.to_string(),
        mx,
        spf,
        dmarc,
        dkim,
        dkim_selectors_checked: checked,
    })
}

// =====================================================================
// Individual lookups
// =====================================================================

type Rsv = Resolver<TokioRuntimeProvider>;

async fn lookup_mx(resolver: &Rsv, domain: &str) -> Vec<MxRecord> {
    let Ok(answers) = resolver.mx_lookup(domain).await else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for rec in answers.answers() {
        let RData::MX(mx) = &rec.data else { continue };
        let exchange = mx.exchange.to_utf8().trim_end_matches('.').to_string();
        // Forward-resolve the exchange to surface DNS-chain breaks.
        let ips: Vec<IpAddr> = resolver
            .lookup_ip(&exchange)
            .await
            .map(|x| x.iter().collect())
            .unwrap_or_default();
        out.push(MxRecord {
            preference: mx.preference,
            exchange,
            ips,
        });
    }
    out.sort_by_key(|r| r.preference);
    out
}

async fn lookup_spf(resolver: &Rsv, domain: &str) -> Option<SpfRecord> {
    let raw = txt_record_matching(resolver, domain, "v=spf1").await?;
    Some(parse_spf(&raw))
}

async fn lookup_dmarc(resolver: &Rsv, domain: &str) -> Option<DmarcRecord> {
    let raw = txt_record_matching(resolver, &format!("_dmarc.{domain}"), "v=DMARC1").await?;
    Some(parse_dmarc(&raw))
}

async fn lookup_dkim(resolver: &Rsv, domain: &str, selector: &str) -> Option<DkimRecord> {
    let name = format!("{selector}._domainkey.{domain}");
    // A DKIM record usually opens with `v=DKIM1`, but that tag is
    // optional (RFC 6376 §3.6.1); the one tag that is *always* present
    // in a real key record is `p=`.  Match on either so we don't miss a
    // valid-but-versionless record.
    let raw = txt_record_starting_with(resolver, &name, &["v=DKIM1", "p=", "k="]).await?;
    Some(parse_dkim(selector, &raw))
}

/// Look up TXT records at `name` and return the first one whose value
/// starts with `prefix` (case-sensitive, per RFCs 4408 / 7489).
async fn txt_record_matching(resolver: &Rsv, name: &str, prefix: &str) -> Option<String> {
    txt_record_starting_with(resolver, name, &[prefix]).await
}

/// Like [`txt_record_matching`] but accepts several acceptable
/// prefixes, returning the first TXT record that begins with **any** of
/// them.  DKIM records may or may not carry the optional `v=DKIM1`
/// prefix, so we accept `p=` / `k=` openings too.
async fn txt_record_starting_with(resolver: &Rsv, name: &str, prefixes: &[&str]) -> Option<String> {
    let answers = resolver.lookup(name, RecordType::TXT).await.ok()?;
    for rec in answers.answers() {
        let RData::TXT(txt) = &rec.data else { continue };
        // A TXT record can be a sequence of multiple <character-string>s
        // (RFC 1035 sec 3.3.14, RFC 7208 sec 3.3); concatenate them to
        // recover the logical record value.
        let joined: String = txt
            .txt_data
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        if prefixes.iter().any(|p| joined.starts_with(p)) {
            return Some(joined);
        }
    }
    None
}

// =====================================================================
// Record parsers (pure - no I/O, easy to test)
// =====================================================================

pub(crate) fn parse_spf(raw: &str) -> SpfRecord {
    let all_qualifier = raw.split_whitespace().find_map(|tok| {
        let (q, m) = if let Some(rest) = tok.strip_prefix(['-', '~', '?', '+']) {
            (&tok[..1], rest)
        } else {
            ("+", tok)
        };
        if m == "all" {
            Some(q.to_string())
        } else {
            None
        }
    });
    SpfRecord {
        raw: raw.to_string(),
        all_qualifier,
    }
}

pub(crate) fn parse_dmarc(raw: &str) -> DmarcRecord {
    let mut record = DmarcRecord {
        raw: raw.to_string(),
        policy: None,
        subdomain_policy: None,
        pct: None,
    };
    for tag in raw.split(';') {
        let (k, v) = match tag.trim().split_once('=') {
            Some(pair) => (pair.0.trim(), pair.1.trim()),
            None => continue,
        };
        match k {
            "p" => record.policy = Some(v.to_string()),
            "sp" => record.subdomain_policy = Some(v.to_string()),
            "pct" => record.pct = v.parse().ok(),
            _ => {}
        }
    }
    record
}

pub(crate) fn parse_dkim(selector: &str, raw: &str) -> DkimRecord {
    let mut version = None;
    let mut key_type = None;
    let mut public_key = None;
    let mut flags = Vec::new();

    for tag in raw.split(';') {
        let (k, v) = match tag.trim().split_once('=') {
            Some(pair) => (pair.0.trim(), pair.1.trim()),
            None => continue,
        };
        match k {
            "v" => version = Some(v.to_string()),
            "k" => key_type = Some(v.to_lowercase()),
            // `p=` base64 can be split across whitespace inside the same
            // <character-string>; strip all internal whitespace so the
            // decoder sees clean base64.
            "p" => {
                public_key = Some(v.split_whitespace().collect::<String>());
            }
            "t" => {
                flags = v
                    .split(':')
                    .map(|f| f.trim().to_string())
                    .filter(|f| !f.is_empty())
                    .collect();
            }
            _ => {}
        }
    }

    // Derive key strength.  ed25519 keys (RFC 8463) are a fixed 256 bits
    // and `p=` is the raw 32-byte key, not an SPKI wrapper; RSA keys
    // carry a DER SubjectPublicKeyInfo whose modulus length we measure.
    let key_bits = match public_key.as_deref() {
        None | Some("") => None,
        Some(p) => {
            let der = base64_decode(p);
            match key_type.as_deref() {
                Some("ed25519") => der.filter(|d| d.len() == 32).map(|_| 256),
                // Default (`rsa`, or the tag omitted) => parse the SPKI.
                _ => der.as_deref().and_then(rsa_modulus_bits),
            }
        }
    };

    DkimRecord {
        selector: selector.to_string(),
        raw: raw.to_string(),
        version,
        key_type,
        public_key,
        flags,
        key_bits,
    }
}

/// Decode a base64 string (standard alphabet, padding optional) into
/// bytes, returning `None` if it is not valid base64.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    // `GeneralPurpose` with `STANDARD` alphabet but *indifferent*
    // padding, because real-world DKIM records are inconsistent about
    // the trailing `=`.
    base64::engine::general_purpose::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::general_purpose::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    )
    .decode(s)
    .ok()
}

/// Measure the RSA modulus size, in bits, of a DER-encoded X.509
/// `SubjectPublicKeyInfo` (what a DKIM `p=` tag holds for an RSA key).
///
/// We deliberately hand-roll a *minimal* DER walk rather than pull in a
/// full crypto/ASN.1 crate: the structure we need is fixed and shallow
/// (`SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey {
/// modulus INTEGER, exponent INTEGER } } }`), we only read lengths - we
/// never trust the key or do crypto with it - and the parser below is a
/// few dozen fully-tested lines. Pulling `rsa`/`spki` for one length
/// measurement would multiply the dep tree for no security gain.
fn rsa_modulus_bits(der: &[u8]) -> Option<u32> {
    let mut r = Der::new(der);
    r.enter_sequence()?; // outer SubjectPublicKeyInfo
    r.skip_field()?; // AlgorithmIdentifier (SEQUENCE) - not needed
    let bitstring = r.read_field(0x03)?; // BIT STRING wrapping the key
                                         // First BIT STRING byte is the count of unused trailing bits
                                         // (0 for a byte-aligned key); the rest is the DER RSAPublicKey.
    let inner = bitstring.split_first().filter(|(pad, _)| **pad == 0)?.1;

    let mut r = Der::new(inner);
    r.enter_sequence()?; // RSAPublicKey
    let modulus = r.read_field(0x02)?; // modulus INTEGER
                                       // A positive DER INTEGER whose top bit is set carries a leading
                                       // 0x00 to keep it unsigned; drop it before measuring.
    let modulus = match modulus.split_first() {
        Some((0x00, rest)) => rest,
        _ => modulus,
    };
    if modulus.is_empty() {
        return None;
    }
    // Bit length of the big-endian modulus: full bytes after the first,
    // plus the significant bits of the leading byte.
    let bits = (modulus.len() as u32 - 1) * 8 + (8 - modulus[0].leading_zeros());
    Some(bits)
}

/// A tiny, allocation-free reader over a DER byte slice.  It knows just
/// enough to walk the fixed SPKI shape above: read a tag+length header,
/// enter a SEQUENCE, skip a field, or read a field's contents by tag.
struct Der<'a> {
    buf: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Der { buf }
    }

    /// Read one `(tag, length)` header, advancing past it, and return
    /// the tag plus the content length.  Handles short-form and
    /// long-form (multi-byte) DER lengths.
    fn header(&mut self) -> Option<(u8, usize)> {
        let (&tag, rest) = self.buf.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (first as usize, rest)
        } else {
            // Long form: low 7 bits = number of length octets.
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let mut len = 0usize;
            for &b in &rest[..n] {
                len = (len << 8) | b as usize;
            }
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        self.buf = rest;
        Some((tag, len))
    }

    /// Enter a SEQUENCE: read its header (tag must be `0x30`) and narrow
    /// the reader to the sequence's contents.
    fn enter_sequence(&mut self) -> Option<()> {
        let (tag, len) = self.header()?;
        if tag != 0x30 {
            return None;
        }
        self.buf = &self.buf[..len];
        Some(())
    }

    /// Read a field of the expected `tag`, returning its content bytes
    /// and advancing past it.
    fn read_field(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (t, len) = self.header()?;
        if t != tag {
            return None;
        }
        let (val, rest) = self.buf.split_at(len);
        self.buf = rest;
        Some(val)
    }

    /// Skip the next field regardless of tag.
    fn skip_field(&mut self) -> Option<()> {
        let (_, len) = self.header()?;
        self.buf = &self.buf[len..];
        Some(())
    }
}

// =====================================================================
// Interpretation - what would IT actually do about this report?
// =====================================================================

/// Convert a `DnsReport` into a flat list of hints, sorted by severity
/// (Critical first).  The English text in each hint is a usable
/// default; the GUI's i18n layer can substitute a localised version
/// keyed by `DnsHint::id`.
pub fn interpret(report: &DnsReport) -> Vec<DnsHint> {
    let mut out = Vec::new();

    // ---- MX ---------------------------------------------------------
    if report.mx.is_empty() {
        out.push(DnsHint {
            id: "no_mx",
            severity: Severity::Critical,
            text: format!(
                "{} has no MX records.  Mail to this domain will bounce \
                 with 'unrouteable address' on every receiver.",
                report.domain
            ),
        });
    } else {
        let mut broken = Vec::new();
        for mx in &report.mx {
            if mx.ips.is_empty() {
                broken.push(mx.exchange.clone());
            }
        }
        if !broken.is_empty() {
            out.push(DnsHint {
                id: "mx_no_a",
                severity: Severity::Critical,
                text: format!(
                    "MX hostname(s) without A/AAAA records: {}.  Receivers \
                     will fail to resolve where to deliver - fix the \
                     forward DNS for these hosts.",
                    broken.join(", ")
                ),
            });
        }
    }

    // ---- SPF --------------------------------------------------------
    match &report.spf {
        None => out.push(DnsHint {
            id: "no_spf",
            severity: Severity::Warning,
            text: format!(
                "{} has no SPF record.  Many receivers (Microsoft 365, \
                 Yahoo, AOL) treat this as 'suspicious' and may junk or \
                 reject the mail.",
                report.domain
            ),
        }),
        Some(spf) => match spf.all_qualifier.as_deref() {
            Some("+") => out.push(DnsHint {
                id: "spf_plus_all",
                severity: Severity::Critical,
                text: format!(
                    "SPF record ends with '+all' - this means 'anyone in \
                     the world may send as {}'.  Effectively no policy. \
                     Change to '-all' (strict) or '~all' (softfail).",
                    report.domain
                ),
            }),
            Some("?") => out.push(DnsHint {
                id: "spf_neutral_all",
                severity: Severity::Warning,
                text: "SPF record ends with '?all' (neutral).  Receivers \
                       cannot use SPF to distinguish legitimate mail \
                       from forgeries.  Tighten to '~all' or '-all'."
                    .to_string(),
            }),
            None => out.push(DnsHint {
                id: "spf_no_all",
                severity: Severity::Warning,
                text: "SPF record has no 'all' mechanism.  Per RFC 7208 \
                       this is treated as 'neutral' by most receivers. \
                       Append '~all' or '-all' to make the policy \
                       explicit."
                    .to_string(),
            }),
            _ => {}
        },
    }

    // ---- DMARC ------------------------------------------------------
    match &report.dmarc {
        None => out.push(DnsHint {
            id: "no_dmarc",
            severity: Severity::Warning,
            text: format!(
                "{} has no DMARC record at _dmarc.{}.  Without DMARC, \
                 receivers will not honour your SPF / DKIM alignment - \
                 spoofing of your domain is harder to block.",
                report.domain, report.domain
            ),
        }),
        Some(d) => {
            match d.policy.as_deref() {
                Some("none") => out.push(DnsHint {
                    id: "dmarc_p_none",
                    severity: Severity::Info,
                    text: "DMARC policy is 'p=none' (monitor-only).  \
                           Useful for the first weeks after deploying \
                           DMARC; tighten to p=quarantine then p=reject \
                           once aggregate reports look clean."
                        .to_string(),
                }),
                Some("quarantine") | Some("reject") => {
                    // Healthy: nothing to flag.
                }
                Some(other) => out.push(DnsHint {
                    id: "dmarc_p_unknown",
                    severity: Severity::Warning,
                    text: format!(
                        "DMARC policy 'p={other}' is not a value any \
                         receiver recognises.  Use 'none', 'quarantine', \
                         or 'reject'."
                    ),
                }),
                None => out.push(DnsHint {
                    id: "dmarc_no_p",
                    severity: Severity::Warning,
                    text: "DMARC record is missing the required 'p=' \
                           tag.  Receivers will ignore the record."
                        .to_string(),
                }),
            }
            if let Some(pct) = d.pct {
                if pct < 100 {
                    out.push(DnsHint {
                        id: "dmarc_pct_low",
                        severity: Severity::Info,
                        text: format!(
                            "DMARC pct={pct}: only that percentage of \
                             non-aligned mail is acted on.  Fine while \
                             rolling out, but raise to pct=100 once \
                             reports are clean."
                        ),
                    });
                }
            }
        }
    }

    // ---- DKIM -------------------------------------------------------
    // Only speak up about DKIM when selectors were actually probed;
    // otherwise an apex-only audit would look like it "found no DKIM".
    if !report.dkim_selectors_checked.is_empty() {
        if report.dkim.is_empty() {
            out.push(DnsHint {
                id: "dkim_none_found",
                severity: Severity::Info,
                text: format!(
                    "No DKIM record found at the selector(s) checked \
                     ({}).  DKIM may still be configured under a \
                     different selector - check the exact selector your \
                     mail provider signs with (it appears in the \
                     'DKIM-Signature:' header's s= tag of a real \
                     message).",
                    report.dkim_selectors_checked.join(", ")
                ),
            });
        }
        for rec in &report.dkim {
            interpret_dkim(rec, &mut out);
        }
    }

    out.sort_by_key(|h| match h.severity {
        Severity::Critical => 0,
        Severity::Warning => 1,
        Severity::Info => 2,
    });
    out
}

/// Append the hints for a single found DKIM record.
fn interpret_dkim(rec: &DkimRecord, out: &mut Vec<DnsHint>) {
    let sel = &rec.selector;

    // Revoked key: `p=` present but empty.  Every signature made with
    // this selector now fails verification.
    if rec.public_key.as_deref() == Some("") {
        out.push(DnsHint {
            id: "dkim_revoked",
            severity: Severity::Critical,
            text: format!(
                "DKIM selector '{sel}' has an empty public key (p=), \
                 which per RFC 6376 means the key is REVOKED.  Any mail \
                 signed with this selector will fail DKIM.  If the \
                 selector is still in use, republish its public key."
            ),
        });
        return; // Nothing else meaningful to say about a revoked key.
    }

    // Malformed: no `p=` tag at all.
    if rec.public_key.is_none() {
        out.push(DnsHint {
            id: "dkim_no_p",
            severity: Severity::Warning,
            text: format!(
                "DKIM selector '{sel}' has no 'p=' (public key) tag, so \
                 it is not a usable key record.  Verifiers will ignore \
                 it."
            ),
        });
        return;
    }

    // Wrong version tag (present but not DKIM1).
    if let Some(v) = &rec.version {
        if !v.eq_ignore_ascii_case("DKIM1") {
            out.push(DnsHint {
                id: "dkim_bad_version",
                severity: Severity::Warning,
                text: format!(
                    "DKIM selector '{sel}' declares v={v}, but the only \
                     valid version is 'DKIM1'.  Some verifiers will \
                     reject the record outright."
                ),
            });
        }
    }

    // Testing mode: t=y tells verifiers to treat this domain as testing
    // and NOT to act on DKIM failures - so it buys no protection.
    if rec.flags.iter().any(|f| f == "y") {
        out.push(DnsHint {
            id: "dkim_testing",
            severity: Severity::Warning,
            text: format!(
                "DKIM selector '{sel}' is in testing mode (t=y): \
                 verifiers are told to ignore DKIM results for it, so it \
                 provides no deliverability or anti-spoofing benefit. \
                 Remove t=y once you have confirmed signing works."
            ),
        });
    }

    // Key strength.  Only RSA has a variable size worth flagging;
    // ed25519 is a fixed, strong 256-bit curve.
    let is_ed25519 = rec.key_type.as_deref() == Some("ed25519");
    if !is_ed25519 {
        match rec.key_bits {
            Some(bits) if bits < 1024 => out.push(DnsHint {
                id: "dkim_key_weak",
                severity: Severity::Critical,
                text: format!(
                    "DKIM selector '{sel}' uses a {bits}-bit RSA key. \
                     Keys under 1024 bits are trivially factorable and \
                     are rejected by Google, Microsoft 365 and others. \
                     Reissue the selector with a 2048-bit key."
                ),
            }),
            Some(1024) => out.push(DnsHint {
                id: "dkim_key_short",
                severity: Severity::Warning,
                text: format!(
                    "DKIM selector '{sel}' uses a 1024-bit RSA key.  It \
                     still verifies today, but 2048 bits is the current \
                     recommendation (and some receivers are phasing 1024 \
                     out).  Plan a rotation to 2048 bits."
                ),
            }),
            Some(_) => {} // >=2048-bit RSA: healthy.
            None => out.push(DnsHint {
                id: "dkim_key_unreadable",
                severity: Severity::Warning,
                text: format!(
                    "DKIM selector '{sel}' has a public key that could \
                     not be decoded as a valid RSA key.  Check for a \
                     corrupted or truncated 'p=' value."
                ),
            }),
        }
    }

    // Unknown key algorithm (something other than rsa / ed25519).
    if let Some(k) = &rec.key_type {
        if k != "rsa" && k != "ed25519" {
            out.push(DnsHint {
                id: "dkim_key_type_unknown",
                severity: Severity::Warning,
                text: format!(
                    "DKIM selector '{sel}' declares an unrecognised key \
                     type 'k={k}'.  Verifiers that do not support it will \
                     treat the signature as broken."
                ),
            });
        }
    }
}

// =====================================================================
// Pretty-printing - used by both the CLI subcommand and the GUI tab.
// =====================================================================

/// Multi-line text rendering of a report + its hints, with no colour
/// escape codes.  Suitable for the GUI's monospace log panel and for
/// the CLI's stdout.
pub fn render_report(report: &DnsReport, hints: &[DnsHint]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "DNS audit for {}", report.domain);
    let _ = writeln!(s, "{}", "-".repeat(20 + report.domain.len()));
    let _ = writeln!(s);

    if report.mx.is_empty() {
        let _ = writeln!(s, "MX:    (none)");
    } else {
        let _ = writeln!(s, "MX:");
        for mx in &report.mx {
            let ips = if mx.ips.is_empty() {
                "<unresolved>".to_string()
            } else {
                mx.ips
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let _ = writeln!(s, "  {:>3}  {:<40}  [{}]", mx.preference, mx.exchange, ips);
        }
    }
    let _ = writeln!(s);

    match &report.spf {
        Some(spf) => {
            let _ = writeln!(s, "SPF:   {}", spf.raw);
            if let Some(q) = &spf.all_qualifier {
                let _ = writeln!(s, "         (all-qualifier: '{q}all')");
            }
        }
        None => {
            let _ = writeln!(s, "SPF:   (none)");
        }
    }
    let _ = writeln!(s);

    match &report.dmarc {
        Some(d) => {
            let _ = writeln!(s, "DMARC: {}", d.raw);
        }
        None => {
            let _ = writeln!(s, "DMARC: (none)");
        }
    }
    let _ = writeln!(s);

    // DKIM: only rendered when selectors were actually probed.
    if !report.dkim_selectors_checked.is_empty() {
        if report.dkim.is_empty() {
            let _ = writeln!(
                s,
                "DKIM:  (none found; checked: {})",
                report.dkim_selectors_checked.join(", ")
            );
        } else {
            let _ = writeln!(s, "DKIM:");
            for rec in &report.dkim {
                let key = if rec.public_key.as_deref() == Some("") {
                    "REVOKED (empty p=)".to_string()
                } else {
                    let kind = rec.key_type.as_deref().unwrap_or("rsa");
                    match rec.key_bits {
                        Some(bits) => format!("{kind}, {bits}-bit"),
                        None => format!("{kind}, key unreadable"),
                    }
                };
                let flags = if rec.flags.is_empty() {
                    String::new()
                } else {
                    format!("  flags: {}", rec.flags.join(":"))
                };
                let _ = writeln!(s, "  {:<12}  {}{}", rec.selector, key, flags);
            }
        }
        let _ = writeln!(s);
    }

    if hints.is_empty() {
        let _ = writeln!(s, "Hints: (none - the basics look healthy)");
    } else {
        let _ = writeln!(s, "Hints:");
        for h in hints {
            let badge = match h.severity {
                Severity::Critical => "[CRIT]",
                Severity::Warning => "[WARN]",
                Severity::Info => "[info]",
            };
            let _ = writeln!(s, "  {badge} {}", h.text);
        }
    }
    s
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SPF parser -------------------------------------------------

    #[test]
    fn spf_parses_minus_all() {
        let r = parse_spf("v=spf1 ip4:192.0.2.0/24 -all");
        assert_eq!(r.all_qualifier.as_deref(), Some("-"));
    }

    #[test]
    fn spf_parses_tilde_all() {
        let r = parse_spf("v=spf1 mx ~all");
        assert_eq!(r.all_qualifier.as_deref(), Some("~"));
    }

    #[test]
    fn spf_parses_plus_all_explicit() {
        let r = parse_spf("v=spf1 +all");
        assert_eq!(r.all_qualifier.as_deref(), Some("+"));
    }

    #[test]
    fn spf_parses_question_all() {
        let r = parse_spf("v=spf1 ?all");
        assert_eq!(r.all_qualifier.as_deref(), Some("?"));
    }

    #[test]
    fn spf_handles_no_all() {
        let r = parse_spf("v=spf1 include:_spf.google.com");
        assert!(r.all_qualifier.is_none());
    }

    // ---- DMARC parser -----------------------------------------------

    #[test]
    fn dmarc_parses_reject_policy() {
        let r = parse_dmarc("v=DMARC1; p=reject; rua=mailto:postmaster@example.com");
        assert_eq!(r.policy.as_deref(), Some("reject"));
        assert!(r.subdomain_policy.is_none());
        assert!(r.pct.is_none());
    }

    #[test]
    fn dmarc_parses_quarantine_with_sp_and_pct() {
        let r = parse_dmarc("v=DMARC1; p=quarantine; sp=reject; pct=50");
        assert_eq!(r.policy.as_deref(), Some("quarantine"));
        assert_eq!(r.subdomain_policy.as_deref(), Some("reject"));
        assert_eq!(r.pct, Some(50));
    }

    #[test]
    fn dmarc_tolerates_whitespace_chaos() {
        let r = parse_dmarc("v=DMARC1 ; p = none ;   pct=100");
        assert_eq!(r.policy.as_deref(), Some("none"));
        assert_eq!(r.pct, Some(100));
    }

    // ---- Interpretation --------------------------------------------

    #[test]
    fn interpret_flags_missing_mx_as_critical() {
        let report = DnsReport {
            domain: "example.com".into(),
            mx: vec![],
            spf: None,
            dmarc: None,
            ..Default::default()
        };
        let hints = interpret(&report);
        assert!(hints.iter().any(|h| h.id == "no_mx"));
        assert!(hints.iter().find(|h| h.id == "no_mx").unwrap().severity == Severity::Critical);
    }

    #[test]
    fn interpret_flags_plus_all_as_critical() {
        let report = DnsReport {
            domain: "example.com".into(),
            mx: vec![MxRecord {
                preference: 10,
                exchange: "mx.example.com".into(),
                ips: vec!["192.0.2.1".parse().unwrap()],
            }],
            spf: Some(parse_spf("v=spf1 +all")),
            dmarc: None,
            ..Default::default()
        };
        let hints = interpret(&report);
        let spf_hint = hints.iter().find(|h| h.id == "spf_plus_all").unwrap();
        assert_eq!(spf_hint.severity, Severity::Critical);
    }

    #[test]
    fn interpret_quiet_when_everything_healthy() {
        let report = DnsReport {
            domain: "example.com".into(),
            mx: vec![MxRecord {
                preference: 10,
                exchange: "mx.example.com".into(),
                ips: vec!["192.0.2.1".parse().unwrap()],
            }],
            spf: Some(parse_spf("v=spf1 mx -all")),
            dmarc: Some(parse_dmarc(
                "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
            )),
            ..Default::default()
        };
        let hints = interpret(&report);
        // Only acceptable hint here would be an info-level one, never
        // critical or warning.
        assert!(hints.iter().all(|h| h.severity == Severity::Info));
    }

    #[test]
    fn render_includes_domain_and_hint_badges() {
        let report = DnsReport {
            domain: "example.com".into(),
            mx: vec![],
            spf: None,
            dmarc: None,
            ..Default::default()
        };
        let hints = interpret(&report);
        let s = render_report(&report, &hints);
        assert!(s.contains("example.com"));
        assert!(s.contains("[CRIT]"));
        assert!(s.contains("(none)"));
    }

    // ---- DKIM parser + key-strength --------------------------------

    // Real SubjectPublicKeyInfo blobs generated with `openssl genrsa`
    // (512 / 1024 / 2048-bit) and `openssl genpkey -algorithm ed25519`,
    // exported as the base64 a DKIM `p=` tag actually carries.
    const RSA512_P: &str = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOI33Xa908s2cIvhCFwdhk6dsGGfSykJTRc5DdnDXO8bZmoLdJwalPnGBWxvyAJeN4I1DuNqBWjUGnJjbvpxKpUCAwEAAQ==";
    const RSA1024_P: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4ho8WT5H4iNYbSEOChrBK8OMi7kKUvUxYBXZPnek76IVjATH6bmolcqXrhqUFNzBsJIthc7H++ec33MG+zZLG6BzPpqJOYe6beD+I6UWJBLySVuJx12Y+kHM9C3AoCiBjw1HD5OanzcjwCt4zNm9hZPnhF1jjvUZLwdlfJGPibwIDAQAB";
    const RSA2048_P: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqSVfi8Fvou9J3wTR92CGXnOqAi9LIVc4LZdnz+1NHxn/N3P2CjIbcLxHzlBAJOV0OIODQ5GYF3JI68OnuFQoUqnOMFY9ajSh1xWrwvjMEQquoTvb/vkj1vMpV5UnqimLRzBcVtdHW90MbzWY96+LYQnsJc1TGtcy504TBqC10WjjGwRmZPISQ5Bb7mrp8tmkX2guGJGfB4DUMsg4CicMvVKGiEHF49EUudJoQvuQOt9PmBHxLcGRxXRS34Lmlp/skDGiK9VJcWVlfMCb1onCzCRC/3hJB6NavmyTr1+DVK5RfSNxOzslIbO5QmGza5YbRHqyXnOAZwRTulwk+eQDxQIDAQAB";
    const ED25519_P: &str = "kOoNv1fwhy+oQ3MYbppmQ0H+et4/u3CafZ3ltNP1JxQ=";

    #[test]
    fn dkim_measures_rsa_key_sizes() {
        assert_eq!(
            parse_dkim("s", &format!("v=DKIM1; k=rsa; p={RSA512_P}")).key_bits,
            Some(512)
        );
        assert_eq!(
            parse_dkim("s", &format!("v=DKIM1; k=rsa; p={RSA1024_P}")).key_bits,
            Some(1024)
        );
        assert_eq!(
            parse_dkim("s", &format!("v=DKIM1; k=rsa; p={RSA2048_P}")).key_bits,
            Some(2048)
        );
    }

    #[test]
    fn dkim_defaults_key_type_to_rsa_and_still_measures() {
        // No k= tag => RSA per RFC 6376; must still decode the SPKI.
        let r = parse_dkim("s", &format!("v=DKIM1; p={RSA2048_P}"));
        assert_eq!(r.key_type, None);
        assert_eq!(r.key_bits, Some(2048));
    }

    #[test]
    fn dkim_ed25519_is_256_bits() {
        let r = parse_dkim("s", &format!("v=DKIM1; k=ed25519; p={ED25519_P}"));
        assert_eq!(r.key_type.as_deref(), Some("ed25519"));
        assert_eq!(r.key_bits, Some(256));
    }

    #[test]
    fn dkim_parses_flags_and_revocation() {
        let r = parse_dkim("s", "v=DKIM1; k=rsa; t=y:s; p=");
        assert_eq!(r.flags, vec!["y".to_string(), "s".to_string()]);
        // Empty p= is present-but-empty (revoked), NOT absent.
        assert_eq!(r.public_key.as_deref(), Some(""));
        assert_eq!(r.key_bits, None);
    }

    #[test]
    fn dkim_tolerates_whitespace_in_base64() {
        // Some zone files wrap the key across character-strings.
        let mangled = RSA2048_P.replacen("qSVf", "qSVf ", 1);
        let r = parse_dkim("s", &format!("v=DKIM1; p={mangled}"));
        assert_eq!(r.key_bits, Some(2048));
    }

    #[test]
    fn dkim_missing_p_tag_is_none() {
        let r = parse_dkim("s", "v=DKIM1; k=rsa");
        assert!(r.public_key.is_none());
        assert!(r.key_bits.is_none());
    }

    // ---- DKIM interpretation ---------------------------------------

    fn report_with_dkim(rec: DkimRecord) -> DnsReport {
        DnsReport {
            domain: "example.com".into(),
            dkim_selectors_checked: vec![rec.selector.clone()],
            dkim: vec![rec],
            ..Default::default()
        }
    }

    #[test]
    fn interpret_flags_revoked_dkim_as_critical() {
        let report = report_with_dkim(parse_dkim("sel1", "v=DKIM1; k=rsa; p="));
        let hints = interpret(&report);
        let h = hints.iter().find(|h| h.id == "dkim_revoked").unwrap();
        assert_eq!(h.severity, Severity::Critical);
    }

    #[test]
    fn interpret_flags_weak_512_bit_key_as_critical() {
        let report = report_with_dkim(parse_dkim("sel1", &format!("v=DKIM1; p={RSA512_P}")));
        let hints = interpret(&report);
        let h = hints.iter().find(|h| h.id == "dkim_key_weak").unwrap();
        assert_eq!(h.severity, Severity::Critical);
    }

    #[test]
    fn interpret_flags_1024_bit_key_as_warning() {
        let report = report_with_dkim(parse_dkim("sel1", &format!("v=DKIM1; p={RSA1024_P}")));
        let hints = interpret(&report);
        assert!(hints
            .iter()
            .any(|h| h.id == "dkim_key_short" && h.severity == Severity::Warning));
    }

    #[test]
    fn interpret_flags_testing_mode() {
        let report = report_with_dkim(parse_dkim("sel1", &format!("v=DKIM1; t=y; p={RSA2048_P}")));
        let hints = interpret(&report);
        assert!(hints.iter().any(|h| h.id == "dkim_testing"));
    }

    #[test]
    fn interpret_quiet_for_healthy_2048_key() {
        let report = report_with_dkim(parse_dkim(
            "sel1",
            &format!("v=DKIM1; k=rsa; p={RSA2048_P}"),
        ));
        let hints = interpret(&report);
        // A healthy DKIM key should raise no DKIM hint of any severity.
        assert!(!hints.iter().any(|h| h.id.starts_with("dkim_")));
    }

    #[test]
    fn interpret_notes_when_selectors_probed_but_none_found() {
        let report = DnsReport {
            domain: "example.com".into(),
            dkim_selectors_checked: vec!["selector1".into(), "google".into()],
            ..Default::default()
        };
        let hints = interpret(&report);
        let h = hints.iter().find(|h| h.id == "dkim_none_found").unwrap();
        assert_eq!(h.severity, Severity::Info);
        assert!(h.text.contains("selector1"));
    }

    #[test]
    fn interpret_silent_on_dkim_when_no_selectors_probed() {
        // An apex-only audit must not imply DKIM is missing.
        let report = DnsReport {
            domain: "example.com".into(),
            ..Default::default()
        };
        let hints = interpret(&report);
        assert!(!hints.iter().any(|h| h.id.starts_with("dkim_")));
    }

    #[test]
    fn render_shows_dkim_section() {
        let report = report_with_dkim(parse_dkim(
            "selector1",
            &format!("v=DKIM1; k=rsa; p={RSA2048_P}"),
        ));
        let s = render_report(&report, &interpret(&report));
        assert!(s.contains("DKIM:"));
        assert!(s.contains("selector1"));
        assert!(s.contains("2048-bit"));
    }

    // ---- Live integration test (network-bound; off by default) -----

    /// Hits live DNS for `outlook.com`.  We only assert that the
    /// **resolver path works** (i.e. we got some MX records back
    /// without panicking); we deliberately do NOT assert specific
    /// SPF / DMARC content because Microsoft tweaks those records
    /// from time to time and we do not want a green-field deploy
    /// to break the build.  Enabled with `cargo test --features
    /// live-net`.
    #[cfg(feature = "live-net")]
    #[test]
    fn live_outlook_audit() {
        let report = audit_domain("outlook.com").unwrap();
        assert!(
            !report.mx.is_empty(),
            "outlook.com should have MX records (got: {:?})",
            report
        );
    }
}
