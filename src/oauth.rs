//! OAuth2 device-code flow (RFC 8628) for Microsoft 365 mailboxes.
//!
//! ## Why this exists
//!
//! Microsoft 365 has been disabling Basic Auth for SMTP / IMAP / POP3
//! tenant-by-tenant since 2022, and the default is now "off" for new
//! tenants.  XOAUTH2 with a short-lived access token is the only
//! sanctioned path forward.  Pasting a token by hand is awkward; the
//! device-code flow lets a CLI / GUI mint the token after the user
//! pops a browser tab to consent.
//!
//! ## Scope (intentionally minimal for v0.2.0)
//!
//! - **Provider**: Microsoft 365 only.  Gmail OAuth needs the caller
//!   to register their own Google Cloud project; that is a much bigger
//!   onboarding step than M365 and we punt it to a later release.
//! - **Client ID**: Mozilla Thunderbird's well-known public ID
//!   (`9e5f94bc-e8a4-4e73-b8be-63364c29d753`).  RFC 8628 \u00a73.2 says\n//!   device-code client_id values are public; this one is documented
//!   widely (mutt-wizard, oauth2ms, isync) and has device-code flow
//!   enabled by Microsoft.  Users on a tenant that locks Conditional
//!   Access to specific app IDs will need to either allow this client
//!   or supply their own via `--oauth-client-id`.
//! - **Tenant**: `common` by default (multi-tenant work + school + MSA).
//! - **Scopes**: `https://outlook.office.com/IMAP.AccessAsUser.All`,
//!   `SMTP.Send`, `POP.AccessAsUser.All`, and `offline_access` so we
//!   get a refresh token.
//!
//! ## Storage
//!
//! Only the `refresh_token` is persisted (in the OS keychain, never
//! the config file - AGENTS.md rule #8).  Access tokens are minted
//! from the refresh on demand because they expire in ~1 hour.
//!
//! ## HTTP transport
//!
//! `ureq 3`, sync, rustls-only.  Matches `lettre`'s `rustls-tls`
//! feature - we already have rustls in the binary so adding ureq's
//! rustls path adds <50 KB.

use serde::Deserialize;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------
// Provider constants
// ---------------------------------------------------------------------

/// Microsoft 365 multi-tenant authority.  `common` accepts work,
/// school, and personal (MSA) accounts.
pub const M365_DEVICE_CODE_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode";

pub const M365_TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";

/// Mozilla Thunderbird's public client ID for Microsoft 365 OAuth.
/// RFC 8628 \u00a73.2: device-code public clients do NOT use a client
/// secret.  This ID is documented in Thunderbird's source tree under
/// `comm/mailnews/base/util/OAuth2Providers.sys.mjs` and is reused by
/// many open-source mail tools (oauth2ms, mutt-wizard, etc.).
pub const M365_DEFAULT_CLIENT_ID: &str = "9e5f94bc-e8a4-4e73-b8be-63364c29d753";

/// Scopes for full mailbox access via SMTP / IMAP / POP plus a refresh
/// token (`offline_access`).  These are Microsoft's documented
/// outlook.office.com scopes.
pub const M365_DEFAULT_SCOPES: &[&str] = &[
    "https://outlook.office.com/IMAP.AccessAsUser.All",
    "https://outlook.office.com/SMTP.Send",
    "https://outlook.office.com/POP.AccessAsUser.All",
    "offline_access",
];

// ---------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------

/// What the device-code endpoint hands back.  The user then opens
/// `verification_uri` in a browser and types `user_code`.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
    pub message: Option<String>,
}

/// What the token endpoint hands back once the user has authorised.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub token_type: String,
    pub scope: Option<String>,
}

/// Errors that can happen along the device-code dance.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("OAuth error: {error}: {description}")]
    OAuth { error: String, description: String },
    #[error("user did not complete authorisation before the device code expired")]
    Expired,
    #[error("polling cancelled")]
    Cancelled,
    #[error("JSON decode failed: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------
// Step 1: ask Microsoft for a device code
// ---------------------------------------------------------------------

/// Initiate the device-code flow against Microsoft 365's `common`
/// endpoint with the default Thunderbird client ID and the IMAP +
/// SMTP + POP + offline_access scopes.
pub fn m365_start() -> Result<DeviceCodeStart, OAuthError> {
    start_device_code(
        M365_DEVICE_CODE_URL,
        M365_DEFAULT_CLIENT_ID,
        M365_DEFAULT_SCOPES,
    )
}

/// Initiate the device-code flow against any RFC-8628 provider.
/// Exposed for users who want to plug their own Azure app registration
/// in, or use a different tenant.
pub fn start_device_code(
    device_code_url: &str,
    client_id: &str,
    scopes: &[&str],
) -> Result<DeviceCodeStart, OAuthError> {
    let body =
        serde_urlencoded::to_string([("client_id", client_id), ("scope", &scopes.join(" "))])
            .map_err(|e| OAuthError::Http(e.to_string()))?;

    let resp = ureq::post(device_code_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .send(body.as_str())
        .map_err(|e| OAuthError::Http(e.to_string()))?;

    let mut resp = resp;
    let text = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| OAuthError::Http(e.to_string()))?;

    let start: DeviceCodeStart = serde_json::from_str(&text)?;
    Ok(start)
}

// ---------------------------------------------------------------------
// Step 2: poll the token endpoint until the user approves or it expires
// ---------------------------------------------------------------------

/// Poll the token endpoint at the cadence the device-code response
/// asked for.  Returns `Ok(TokenResponse)` once the user authorises
/// in their browser, `Err(OAuthError::Expired)` on timeout.
///
/// `cancel` is checked between polls; pass an `AtomicBool` driven by
/// a Cancel button in the GUI, or a no-op closure from the CLI.
pub fn m365_poll(
    start: &DeviceCodeStart,
    mut cancel: impl FnMut() -> bool,
) -> Result<TokenResponse, OAuthError> {
    poll_token(M365_TOKEN_URL, M365_DEFAULT_CLIENT_ID, start, &mut cancel)
}

pub fn poll_token(
    token_url: &str,
    client_id: &str,
    start: &DeviceCodeStart,
    cancel: &mut dyn FnMut() -> bool,
) -> Result<TokenResponse, OAuthError> {
    let deadline = Instant::now() + Duration::from_secs(start.expires_in);
    let mut interval = Duration::from_secs(start.interval.max(1));

    while Instant::now() < deadline {
        if cancel() {
            return Err(OAuthError::Cancelled);
        }
        std::thread::sleep(interval);

        let body = serde_urlencoded::to_string([
            ("client_id", client_id),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &start.device_code),
        ])
        .map_err(|e| OAuthError::Http(e.to_string()))?;

        // We have to inspect 4xx bodies (authorization_pending /
        // slow_down) so we set http_status_as_error to false.
        let resp = ureq::config::Config::builder()
            .http_status_as_error(false)
            .build()
            .new_agent()
            .post(token_url)
            .header("content-type", "application/x-www-form-urlencoded")
            .send(body.as_str())
            .map_err(|e| OAuthError::Http(e.to_string()))?;

        let mut resp = resp;
        let status = resp.status().as_u16();
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| OAuthError::Http(e.to_string()))?;

        if status == 200 {
            return Ok(serde_json::from_str(&text)?);
        }
        // Non-200 bodies are OAuth error responses per RFC 6749 \u00a75.2.
        let err: OAuthErrBody = serde_json::from_str(&text)?;
        match err.error.as_str() {
            // Keep polling at the same cadence.
            "authorization_pending" => continue,
            // RFC 8628 \u00a73.5: server tells us to back off.
            "slow_down" => {
                interval = interval.saturating_add(Duration::from_secs(5));
                continue;
            }
            // Permanent failures.
            "expired_token" => return Err(OAuthError::Expired),
            "access_denied" => {
                return Err(OAuthError::OAuth {
                    error: err.error,
                    description: err
                        .error_description
                        .unwrap_or_else(|| "user denied".to_string()),
                })
            }
            other => {
                return Err(OAuthError::OAuth {
                    error: other.to_string(),
                    description: err.error_description.unwrap_or_default(),
                })
            }
        }
    }
    Err(OAuthError::Expired)
}

#[derive(Debug, Deserialize)]
struct OAuthErrBody {
    error: String,
    error_description: Option<String>,
}

// ---------------------------------------------------------------------
// Step 3: refresh access token from a stored refresh token
// ---------------------------------------------------------------------

/// Trade a refresh token for a new access token.  Call this when the
/// stored access token has expired (or just always, before each XOAUTH2
/// session - access tokens are cheap to mint).
pub fn m365_refresh(refresh_token: &str) -> Result<TokenResponse, OAuthError> {
    refresh_access_token(M365_TOKEN_URL, M365_DEFAULT_CLIENT_ID, refresh_token)
}

pub fn refresh_access_token(
    token_url: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenResponse, OAuthError> {
    let body = serde_urlencoded::to_string([
        ("client_id", client_id),
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ])
    .map_err(|e| OAuthError::Http(e.to_string()))?;

    let resp = ureq::post(token_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .send(body.as_str())
        .map_err(|e| OAuthError::Http(e.to_string()))?;

    let mut resp = resp;
    let text = resp
        .body_mut()
        .read_to_string()
        .map_err(|e| OAuthError::Http(e.to_string()))?;

    Ok(serde_json::from_str(&text)?)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_device_code_start_response() {
        let body = r#"{
            "user_code": "AB12CD34",
            "device_code": "GCG2pjefT8GbQHIY1zWNcyrk6vh3pTfYSj",
            "verification_uri": "https://microsoft.com/devicelogin",
            "expires_in": 900,
            "interval": 5,
            "message": "To sign in, use a web browser..."
        }"#;
        let r: DeviceCodeStart = serde_json::from_str(body).unwrap();
        assert_eq!(r.user_code, "AB12CD34");
        assert_eq!(r.interval, 5);
    }

    #[test]
    fn parses_token_response() {
        let body = r#"{
            "access_token": "eyJ0eXAi...",
            "refresh_token": "0.AS8AABC...",
            "expires_in": 3599,
            "token_type": "Bearer",
            "scope": "offline_access IMAP.AccessAsUser.All"
        }"#;
        let r: TokenResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.token_type, "Bearer");
        assert!(r.refresh_token.is_some());
    }

    #[test]
    fn parses_oauth_error_pending() {
        let body = r#"{
            "error": "authorization_pending",
            "error_description": "User has not yet completed sign-in."
        }"#;
        let e: OAuthErrBody = serde_json::from_str(body).unwrap();
        assert_eq!(e.error, "authorization_pending");
    }

    #[test]
    fn m365_defaults_use_common_tenant() {
        assert!(M365_DEVICE_CODE_URL.contains("/common/"));
        assert!(M365_TOKEN_URL.contains("/common/"));
        assert_eq!(M365_DEFAULT_SCOPES.len(), 4);
        assert!(M365_DEFAULT_SCOPES.contains(&"offline_access"));
    }

    /// Optional: hit the live device-code endpoint, get a real
    /// `user_code` / `verification_uri` back.  We do NOT then prompt
    /// the user - this is just a "the network path works" smoke test.
    #[cfg(feature = "live-net")]
    #[test]
    fn live_m365_start() {
        let start = m365_start().expect("device-code start");
        assert!(!start.device_code.is_empty());
        assert!(!start.user_code.is_empty());
        assert!(start.verification_uri.starts_with("https://"));
        assert!(start.interval >= 1);
    }
}
