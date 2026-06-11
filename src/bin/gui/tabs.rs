//! Per-tab view code for the GUI.
//!
//! Each `tab_*` function renders one tab into the supplied `egui::Ui`,
//! reading and writing the shared [`App`] state.  As a child module of
//! the binary root it can touch `App`'s private fields directly.

use super::palette::theme_label;
use super::App;
use eframe::egui;
use smtp_test_tool::diagnostics::smtp_hints_for;
use smtp_test_tool::i18n::{self, t, t_with};
use smtp_test_tool::theme::ThemeChoice;
use smtp_test_tool::tls::Security;

pub(crate) fn tab_servers(ui: &mut egui::Ui, a: &mut App) {
    // Credentials: use ui.horizontal() rows (like proto_block) rather than
    // a Grid, because Grid sizes cells by intrinsic content and never
    // grows text-edits.  We left-align labels to a fixed width column
    // (LABEL_W) so they line up vertically, then hand the remainder of
    // the row to the entry.
    const LABEL_W: f32 = 100.0;
    const SHOW_W: f32 = 70.0; // approx "☑ Show" checkbox
    const HINT_W: f32 = 160.0; // approx "(XOAUTH2, optional)"

    ui.horizontal(|ui| {
        ui.add_sized([LABEL_W, 0.0], egui::Label::new(t("ui.servers.username")));
        let mut u = a.profile.user.clone().unwrap_or_default();
        let resp = ui.add_sized(
            [ui.available_width(), 0.0],
            egui::TextEdit::singleline(&mut u),
        );
        if resp.changed() {
            a.profile.user = Some(u).filter(|s| !s.is_empty());
        }
    });
    ui.horizontal(|ui| {
        ui.add_sized([LABEL_W, 0.0], egui::Label::new(t("ui.servers.password")));
        let mut pwd = a.profile.password.clone().unwrap_or_default();
        let entry_w = (ui.available_width() - SHOW_W).max(80.0);
        let resp = ui.add_sized(
            [entry_w, 0.0],
            egui::TextEdit::singleline(&mut pwd).password(!a.show_pwd),
        );
        if resp.changed() {
            a.profile.password = Some(pwd).filter(|s| !s.is_empty());
        }
        ui.checkbox(&mut a.show_pwd, t("ui.servers.show"));
    });
    ui.horizontal(|ui| {
        ui.add_sized(
            [LABEL_W, 0.0],
            egui::Label::new(t("ui.servers.oauth_token")),
        );
        let mut token = a.profile.oauth_token.clone().unwrap_or_default();
        let entry_w = (ui.available_width() - HINT_W).max(80.0);
        let resp = ui.add_sized(
            [entry_w, 0.0],
            egui::TextEdit::singleline(&mut token).password(true),
        );
        if resp.changed() {
            a.profile.oauth_token = Some(token).filter(|s| !s.is_empty());
        }
        ui.add_sized(
            [HINT_W, 0.0],
            egui::Label::new(egui::RichText::new(t("ui.servers.oauth_hint")).weak()),
        );
    });

    // OS keychain controls (Windows Credential Manager / macOS Keychain /
    // Linux Secret Service).  Buttons are explicit (no auto-save) so the
    // user always knows when a secret is being persisted.  Per AGENTS.md
    // rule #8 this is the ONE approved store outside process memory.
    ui.horizontal(|ui| {
        ui.add_sized([LABEL_W, 0.0], egui::Label::new(""));
        let user_set = a
            .profile
            .user
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let pwd_set = a
            .profile
            .password
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        if ui
            .add_enabled(
                user_set && pwd_set,
                egui::Button::new(t("ui.servers.save_to_keychain")),
            )
            .on_hover_text(t("ui.servers.save_to_keychain_tooltip"))
            .clicked()
        {
            if let (Some(u), Some(p)) = (&a.profile.user, &a.profile.password) {
                match a.keystore.save(u, p) {
                    Ok(()) => {
                        tracing::info!("saved password for {u} to OS keychain");
                        a.password_from_keychain = true;
                    }
                    Err(e) => tracing::error!("keychain save failed for {u}: {e:#}"),
                }
            }
        }
        if ui
            .add_enabled(user_set, egui::Button::new(t("ui.servers.forget_keychain")))
            .on_hover_text(t("ui.servers.forget_keychain_tooltip"))
            .clicked()
        {
            if let Some(u) = &a.profile.user.clone() {
                match a.keystore.forget(u) {
                    Ok(()) => {
                        tracing::info!("forgot keychain entry for {u}");
                        a.profile.password = None;
                        a.password_from_keychain = false;
                    }
                    Err(e) => tracing::error!("keychain forget failed for {u}: {e:#}"),
                }
            }
        }
        if a.password_from_keychain {
            ui.label(egui::RichText::new(t("ui.servers.loaded_from_keychain")).weak());
        }
        #[cfg(feature = "oauth")]
        {
            let user_set = a
                .profile
                .user
                .as_deref()
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if ui
                .add_enabled(
                    user_set && !a.oauth_login_running,
                    egui::Button::new(t("ui.servers.oauth_login_m365")),
                )
                .on_hover_text(t("ui.servers.oauth_login_m365_tooltip"))
                .clicked()
            {
                let user = a.profile.user.clone().unwrap_or_default();
                let (tx, rx) = std::sync::mpsc::channel();
                a.oauth_login_rx = Some(rx);
                a.oauth_login_running = true;
                a.oauth_login_status.clear();
                let ctx = ui.ctx().clone();
                std::thread::spawn(move || {
                    let _ = tx.send(OauthJobMsg::Status(
                        "Contacting Microsoft for a device code...".into(),
                    ));
                    let start = match smtp_test_tool::oauth::m365_start() {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = tx.send(OauthJobMsg::Failed(e.to_string()));
                            ctx.request_repaint();
                            return;
                        }
                    };
                    let msg = start.message.clone().unwrap_or_else(|| {
                        format!(
                            "Open {} and enter the code {}",
                            start.verification_uri, start.user_code
                        )
                    });
                    let _ = tx.send(OauthJobMsg::Status(msg));
                    ctx.request_repaint();
                    // Open the verification URI in the user's default
                    // browser (best-effort; ignore failure).
                    let _ = webbrowser::open(&start.verification_uri);
                    match smtp_test_tool::oauth::m365_poll(&start, || false) {
                        Ok(tok) => {
                            let _ = tx.send(OauthJobMsg::Done {
                                user,
                                refresh_token: tok.refresh_token.clone(),
                                expires_in: tok.expires_in,
                                access_token: tok.access_token,
                            });
                            ctx.request_repaint();
                        }
                        Err(e) => {
                            let _ = tx.send(OauthJobMsg::Failed(e.to_string()));
                            ctx.request_repaint();
                        }
                    }
                });
            }
            if a.oauth_login_running && !a.oauth_login_status.is_empty() {
                ui.label(
                    egui::RichText::new(&a.oauth_login_status)
                        .small()
                        .italics(),
                );
            }
            // Drain the channel each frame.
            if let Some(rx) = a.oauth_login_rx.as_ref() {
                if let Ok(msg) = rx.try_recv() {
                    match msg {
                        OauthJobMsg::Status(s) => {
                            a.oauth_login_status = s;
                        }
                        OauthJobMsg::Done {
                            user,
                            refresh_token,
                            expires_in,
                            access_token,
                        } => {
                            a.oauth_login_running = false;
                            a.oauth_login_rx = None;
                            if let Some(rt) = refresh_token {
                                match a
                                    .keystore
                                    .save(&format!("oauth-refresh:{user}"), &rt)
                                {
                                    Ok(()) => tracing::info!(
                                        "stored M365 refresh token for {user} (access expires {expires_in}s)"
                                    ),
                                    Err(e) => tracing::error!(
                                        "keychain save failed for oauth-refresh:{user}: {e:#}"
                                    ),
                                }
                            }
                            a.profile.oauth_token = Some(access_token);
                            a.oauth_login_status =
                                "Sign-in complete - access token loaded for this session.".into();
                        }
                        OauthJobMsg::Failed(e) => {
                            a.oauth_login_running = false;
                            a.oauth_login_rx = None;
                            tracing::warn!("M365 OAuth sign-in failed: {e}");
                            a.oauth_login_status = format!("sign-in failed: {e}");
                        }
                    }
                }
            }
        }
    });

    ui.separator();
    proto_block(
        ui,
        "SMTP",
        &mut a.profile.smtp_enabled,
        &mut a.profile.smtp_host,
        &mut a.profile.smtp_port,
        &mut a.profile.smtp_security,
    );
    proto_block(
        ui,
        "IMAP",
        &mut a.profile.imap_enabled,
        &mut a.profile.imap_host,
        &mut a.profile.imap_port,
        &mut a.profile.imap_security,
    );
    proto_block(
        ui,
        "POP3",
        &mut a.profile.pop_enabled,
        &mut a.profile.pop_host,
        &mut a.profile.pop_port,
        &mut a.profile.pop_security,
    );
}

fn proto_block(
    ui: &mut egui::Ui,
    name: &str,
    enabled: &mut bool,
    host: &mut String,
    port: &mut u16,
    sec: &mut Security,
) {
    ui.horizontal(|ui| {
        // Key lookup per protocol so each row gets the localised
        // 'Test SMTP' / 'Test IMAP' / 'Test POP3' label.
        let proto_key = name.to_ascii_lowercase();
        ui.checkbox(enabled, t(&format!("ui.proto.test_{proto_key}")));
        ui.label(t("ui.proto.host"));
        ui.text_edit_singleline(host);
        ui.label(t("ui.proto.port"));
        ui.add(egui::DragValue::new(port).range(1..=65535));
        ui.label(t("ui.proto.security"));
        egui::ComboBox::from_id_salt(format!("{name}-sec"))
            .selected_text(sec.as_str())
            .show_ui(ui, |ui| {
                ui.selectable_value(sec, Security::None, "none");
                ui.selectable_value(sec, Security::StartTls, "starttls");
                ui.selectable_value(sec, Security::Implicit, "ssl");
            });
    });
}

pub(crate) fn tab_send(ui: &mut egui::Ui, a: &mut App) {
    ui.checkbox(&mut a.profile.send_test, t("ui.send.toggle"));
    ui.separator();
    egui::Grid::new("msg").num_columns(2).show(ui, |ui| {
        opt_line(ui, &t("ui.send.mail_from"), &mut a.profile.mail_from);
        opt_line(ui, &t("ui.send.from_header"), &mut a.profile.from_addr);
        ui.label(t("ui.send.to"));
        ui.text_edit_singleline(&mut a.to_csv);
        ui.end_row();
        ui.label(t("ui.send.cc"));
        ui.text_edit_singleline(&mut a.cc_csv);
        ui.end_row();
        ui.label(t("ui.send.bcc"));
        ui.text_edit_singleline(&mut a.bcc_csv);
        ui.end_row();
        opt_line(ui, &t("ui.send.reply_to"), &mut a.profile.reply_to);
        ui.label(t("ui.send.subject"));
        ui.text_edit_singleline(&mut a.profile.subject);
        ui.end_row();
    });
    ui.label(t("ui.send.body"));
    ui.add(
        egui::TextEdit::multiline(&mut a.profile.body)
            .desired_rows(6)
            .desired_width(f32::INFINITY),
    );
}

fn opt_line(ui: &mut egui::Ui, label: &str, v: &mut Option<String>) {
    ui.label(label);
    let mut buf = v.clone().unwrap_or_default();
    if ui.text_edit_singleline(&mut buf).changed() {
        *v = if buf.is_empty() { None } else { Some(buf) };
    }
    ui.end_row();
}

pub(crate) fn tab_tls(ui: &mut egui::Ui, a: &mut App) {
    ui.checkbox(&mut a.profile.insecure_tls, t("ui.tls.insecure"));
    ui.horizontal(|ui| {
        ui.label(t("ui.tls.ca_bundle"));
        let mut buf = a
            .profile
            .ca_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        if ui.text_edit_singleline(&mut buf).changed() {
            a.profile.ca_file = if buf.is_empty() {
                None
            } else {
                Some(buf.into())
            };
        }
    });
}

pub(crate) fn tab_advanced(ui: &mut egui::Ui, a: &mut App) {
    egui::Grid::new("adv").num_columns(2).show(ui, |ui| {
        ui.label(t("ui.advanced.timeout"));
        ui.add(egui::DragValue::new(&mut a.profile.timeout_secs).range(1..=600));
        ui.end_row();

        ui.label(t("ui.advanced.ehlo"));
        let mut e = a.profile.ehlo_name.clone().unwrap_or_default();
        if ui.text_edit_singleline(&mut e).changed() {
            a.profile.ehlo_name = if e.is_empty() { None } else { Some(e) };
        }
        ui.end_row();

        ui.label(t("ui.advanced.imap_folder"));
        ui.text_edit_singleline(&mut a.profile.imap_folder);
        ui.end_row();

        ui.label(t("ui.advanced.log_level"));
        egui::ComboBox::from_id_salt("loglvl")
            .selected_text(&a.profile.log_level)
            .show_ui(ui, |ui| {
                for lv in ["trace", "debug", "info", "warn", "error"] {
                    ui.selectable_value(&mut a.profile.log_level, lv.into(), lv);
                }
            });
        ui.end_row();

        ui.label(t("ui.advanced.theme"));
        let mut current = ThemeChoice::from_config_str(&a.profile.theme);
        let previous = current;
        egui::ComboBox::from_id_salt("themechoice")
            .selected_text(theme_label(current, a.os_appearance))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut current,
                    ThemeChoice::Auto,
                    theme_label(ThemeChoice::Auto, a.os_appearance),
                );
                ui.selectable_value(&mut current, ThemeChoice::Dark, t("ui.advanced.theme_dark"));
                ui.selectable_value(
                    &mut current,
                    ThemeChoice::Light,
                    t("ui.advanced.theme_light"),
                );
            });
        if current != previous {
            a.profile.theme = current.as_str().to_string();
        }
        ui.end_row();

        // Language selector.  Per design: only the user's OS locale
        // (if we ship a translation for it) + English.  This keeps the
        // combo box short and obvious even when the binary ships 25
        // locales.  Picking a value writes profile.locale and applies
        // immediately via i18n::set_locale.
        ui.label(t("ui.advanced.language"));
        let current_code = i18n::current_locale();
        let os_code = a.os_locale_code.as_deref();
        let os_supported = os_code
            .map(|c| i18n::is_supported(c) && c != i18n::BASE)
            .unwrap_or(false);
        let display_label = |code: &str| -> String {
            // "Nederlands (nl)" / "English (en)"
            format!("{} ({code})", i18n::native_name(code))
        };
        egui::ComboBox::from_id_salt("langchoice")
            .selected_text(display_label(&current_code))
            .show_ui(ui, |ui| {
                if os_supported {
                    if let Some(c) = os_code {
                        let selected = current_code == c;
                        if ui.selectable_label(selected, display_label(c)).clicked() && !selected {
                            i18n::set_locale(c);
                            a.profile.locale = Some(c.to_string());
                        }
                    }
                }
                let en_selected = current_code == i18n::BASE;
                if ui
                    .selectable_label(en_selected, display_label(i18n::BASE))
                    .clicked()
                    && !en_selected
                {
                    i18n::set_locale(i18n::BASE);
                    a.profile.locale = Some(i18n::BASE.to_string());
                }
            });
        if !os_supported {
            if let Some(code) = os_code {
                ui.label(
                    egui::RichText::new(t_with(
                        "ui.advanced.language_unsupported",
                        &[("code", code)],
                    ))
                    .weak(),
                );
            }
        }
        ui.end_row();
    });
}

/// Paste-a-bounce diagnostic.  Runs the bounce body through the same
/// `smtp_hints_for` translator that live tests use, so a user who got a
/// bounce in their main mail client can find out what to ask IT for
/// without re-running the protocol against the server.
pub(crate) fn tab_diagnose(ui: &mut egui::Ui, a: &mut App) {
    ui.label(t("ui.diagnose.intro"));
    ui.add_space(6.0);

    let avail_h = ui.available_height();
    // Reserve space for the action row + result panel underneath; tune
    // to ~40 % of the tab body so the result is always visible without
    // scrolling.
    let input_h = (avail_h * 0.4).clamp(120.0, 260.0);
    ui.add_sized(
        [ui.available_width(), input_h],
        egui::TextEdit::multiline(&mut a.diagnose_input)
            .hint_text(t("ui.diagnose.input_placeholder"))
            .desired_rows(8),
    );

    ui.horizontal(|ui| {
        let has_input = !a.diagnose_input.trim().is_empty();
        if ui
            .add_enabled(has_input, egui::Button::new(t("ui.diagnose.analyse")))
            .clicked()
        {
            a.diagnose_hints = smtp_hints_for(&a.diagnose_input);
            if a.diagnose_hints.is_empty() {
                tracing::info!("diagnose: no known patterns matched");
            } else {
                tracing::info!(
                    "diagnose: {} hint line(s) generated",
                    a.diagnose_hints.len()
                );
            }
        }
        if ui.button(t("ui.diagnose.clear")).clicked() {
            a.diagnose_input.clear();
            a.diagnose_hints.clear();
        }
    });

    ui.add_space(8.0);
    ui.separator();
    ui.label(egui::RichText::new(t("ui.diagnose.hints_heading")).strong());
    if a.diagnose_hints.is_empty() {
        ui.label(egui::RichText::new(t("ui.diagnose.no_hints_yet")).weak());
    } else {
        egui::ScrollArea::vertical()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                for line in &a.diagnose_hints {
                    ui.label(egui::RichText::new(line).monospace());
                }
            });
    }
}

// -----------------------------------------------------------------------
// DNS tab
// -----------------------------------------------------------------------
#[cfg(feature = "dns")]
pub(crate) struct DnsJobResult {
    domain: String,
    res: Result<smtp_test_tool::dns::DnsReport, String>,
}

#[cfg(feature = "oauth")]
pub(crate) enum OauthJobMsg {
    Status(String),
    Done {
        user: String,
        refresh_token: Option<String>,
        expires_in: u64,
        access_token: String,
    },
    Failed(String),
}

#[cfg(feature = "dns")]
pub(crate) fn tab_dns(ui: &mut egui::Ui, a: &mut App) {
    ui.label(t("ui.dns.intro"));
    ui.add_space(6.0);

    // Poll the background job channel for completion.
    if let Some(rx) = a.dns_rx.as_ref() {
        if let Ok(done) = rx.try_recv() {
            a.dns_running = false;
            a.dns_rx = None;
            match done.res {
                Ok(report) => {
                    tracing::info!("dns: {} audited", done.domain);
                    a.dns_hints = smtp_test_tool::dns::interpret(&report);
                    a.dns_report = Some(report);
                }
                Err(e) => {
                    tracing::warn!("dns: audit of {} failed: {e}", done.domain);
                    a.dns_report = None;
                    a.dns_hints.clear();
                }
            }
            ui.ctx().request_repaint();
        }
    }

    ui.horizontal(|ui| {
        ui.label(t("ui.dns.domain"));
        ui.add_enabled(
            !a.dns_running,
            egui::TextEdit::singleline(&mut a.dns_domain)
                .hint_text("example.com")
                .desired_width(280.0),
        );
        let has_domain = !a.dns_domain.trim().is_empty();
        let label = if a.dns_running {
            t("ui.dns.running")
        } else {
            t("ui.dns.audit")
        };
        if ui
            .add_enabled(has_domain && !a.dns_running, egui::Button::new(label))
            .clicked()
        {
            let domain = a.dns_domain.trim().to_string();
            let (tx, rx) = std::sync::mpsc::channel();
            a.dns_rx = Some(rx);
            a.dns_running = true;
            let ctx = ui.ctx().clone();
            std::thread::spawn(move || {
                let res = smtp_test_tool::dns::audit_domain(&domain).map_err(|e| e.to_string());
                let _ = tx.send(DnsJobResult { domain, res });
                ctx.request_repaint();
            });
        }
        if ui.button(t("ui.dns.clear")).clicked() {
            a.dns_domain.clear();
            a.dns_report = None;
            a.dns_hints.clear();
        }
    });

    ui.add_space(8.0);
    ui.separator();

    match &a.dns_report {
        None => {
            ui.label(
                egui::RichText::new(if a.dns_running {
                    t("ui.dns.running")
                } else {
                    t("ui.dns.no_results_yet")
                })
                .weak(),
            );
        }
        Some(report) => {
            let text = smtp_test_tool::dns::render_report(report, &a.dns_hints);
            egui::ScrollArea::vertical()
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut text.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(20),
                    );
                });
        }
    }
}
