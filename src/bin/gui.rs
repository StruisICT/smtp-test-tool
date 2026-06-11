//! eframe / egui GUI for smtp-test-tool.
//!
//! * Single static binary, no external runtime needed.
//! * Auto-follows OS dark/light via the `theme` module.
//! * AccessKit screen-reader integration is enabled via the eframe feature.
//! * All status conveyed in text too - colour is never the only signal.
//!
//! The view is split across child modules so no single file gets
//! unwieldy (AGENTS.md rule #5):
//!
//! - `logging`: the tracing Layer that feeds the log panel.
//! - `palette`: theme visuals + WCAG-AAA status colours.
//! - `tabs`: per-tab render functions.
//!
//! This root module owns the `App` state and the eframe update loop.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

// `gui.rs` is the binary crate root, so `mod foo;` would resolve to
// `src/bin/foo.rs` (a sibling) - and each such file would also be picked
// up as its own binary target. Point the submodules at the `gui/`
// subdirectory explicitly to keep them as private modules of this bin.
#[path = "gui/logging.rs"]
mod logging;
#[path = "gui/palette.rs"]
mod palette;
#[path = "gui/tabs.rs"]
mod tabs;

use eframe::egui;
use logging::{GuiLayer, LogLine, LogSink};
use palette::{level_style, outcome_chip, target_label, visuals_for};
use smtp_test_tool::config::{default_save_path, discover_config_path, Config};
use smtp_test_tool::fonts;
use smtp_test_tool::i18n::{self, t};
use smtp_test_tool::keystore::{default_keystore, Keystore};
use smtp_test_tool::locale as os_locale;
use smtp_test_tool::providers::{self, Provider};
use smtp_test_tool::runner::TestResults;
use smtp_test_tool::theme::{detect as detect_appearance, Appearance, ThemeChoice};
use smtp_test_tool::{outlook_defaults, run_tests, Profile};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[cfg(feature = "oauth")]
use tabs::OauthJobMsg;
use tabs::{tab_advanced, tab_diagnose, tab_send, tab_servers, tab_tls};
#[cfg(feature = "dns")]
use tabs::{tab_dns, DnsJobResult};

// -----------------------------------------------------------------------
// Application state
// -----------------------------------------------------------------------
struct App {
    cfg_path: Option<PathBuf>,
    cfg: Config,
    profile_name: String,
    profile: Profile,
    log_sink: Arc<LogSink>,
    log_buf: Vec<LogLine>,
    show_pwd: bool,
    busy: bool,
    /// Native credential store handle.  `Box<dyn>` so unit tests of the
    /// surrounding logic could swap in a mock; the trait is `Send+Sync`
    /// so it's safe to share across the background test thread (we
    /// don't currently, but the type promises it).
    keystore: Box<dyn Keystore>,
    /// Set to true when the current `profile.password` came out of the
    /// OS keychain (auto-loaded on startup).  Surfaces a small textual
    /// hint next to the credentials block so the user knows the
    /// password they see was restored, not just typed.
    password_from_keychain: bool,
    result_rx: Option<Receiver<TestResults>>,
    last_results: TestResults,
    to_csv: String,
    cc_csv: String,
    bcc_csv: String,
    tab: Tab,
    /// Multi-line buffer behind the *Diagnose* tab.  Persisted across
    /// frames but not across launches (would be a privacy hazard - real
    /// bounce bodies often contain headers).
    /// Domain typed into the DNS tab; persisted with the rest of the
    /// GUI state via eframe's storage.
    #[cfg(feature = "dns")]
    dns_domain: String,
    /// Last completed DNS audit + its hints.  None until the user has
    /// clicked "Audit" at least once.
    #[cfg(feature = "dns")]
    dns_report: Option<smtp_test_tool::dns::DnsReport>,
    #[cfg(feature = "dns")]
    dns_hints: Vec<smtp_test_tool::dns::DnsHint>,
    /// Background-job state for the DNS audit so the GUI does not
    /// block on slow resolvers.
    #[cfg(feature = "dns")]
    dns_running: bool,
    #[cfg(feature = "dns")]
    dns_rx: Option<std::sync::mpsc::Receiver<DnsJobResult>>,

    /// Background-job state for the M365 OAuth device-code flow.
    #[cfg(feature = "oauth")]
    oauth_login_running: bool,
    #[cfg(feature = "oauth")]
    oauth_login_status: String,
    #[cfg(feature = "oauth")]
    oauth_login_rx: Option<std::sync::mpsc::Receiver<OauthJobMsg>>,

    diagnose_input: String,
    /// Last result of running `smtp_hints_for` on `diagnose_input`,
    /// rendered as a bullet list under the *Analyse* button.
    diagnose_hints: Vec<String>,
    /// What the OS reported at startup; cached so 'Follow OS' does not
    /// re-shell-out to `defaults` / `gsettings` every frame.
    os_appearance: Appearance,
    /// OS-reported language code (e.g. `Some("nl")`) at startup;
    /// cached because sys-locale touches the registry / a subprocess
    /// on first call.  Drives the Language combobox on the Advanced
    /// tab: the picker offers en + this (if shipped + not en) only.
    os_locale_code: Option<String>,
    /// Last appearance we actually applied via `Context::set_visuals`;
    /// lets us re-apply only on real change.
    applied_appearance: Appearance,
}

#[derive(PartialEq, Copy, Clone)]
enum Tab {
    Servers,
    Send,
    Tls,
    Advanced,
    /// Paste a bounce message body and get IT-actionable hints via the
    /// same `smtp_hints_for` translator that powers the live tests.
    Diagnose,
    /// Run an MX / SPF / DMARC audit against a domain (gated by the
    /// `dns` feature; tab is hidden in CLI-only builds).
    #[cfg(feature = "dns")]
    Dns,
}

impl App {
    fn new(sink: Arc<LogSink>, cc: &eframe::CreationContext<'_>) -> Self {
        // Load config FIRST so we can honour the user's theme choice
        // (rule #4: dark + light, with manual override).
        let cfg_path = discover_config_path();
        // Surface any parse error so the user knows their config was
        // ignored - silent fallback used to mask real bugs.
        let cfg = cfg_path
            .as_ref()
            .and_then(|p| match Config::load(p) {
                Ok(c) => {
                    tracing::info!("loaded config {}", p.display());
                    Some(c)
                }
                Err(e) => {
                    tracing::warn!("failed to load config {}: {:#}", p.display(), e);
                    None
                }
            })
            .unwrap_or_else(|| Config {
                active: "default".into(),
                profiles: [("default".into(), outlook_defaults())]
                    .into_iter()
                    .collect(),
            });
        let profile_name = cfg.active.clone();
        let mut profile = cfg
            .profile(&profile_name)
            .cloned()
            .unwrap_or_else(outlook_defaults);

        // Best-effort keychain auto-load: if a user is known and an
        // entry exists in the OS-native store, populate the password
        // field.  Silent on a miss; logs a warning only on real backend
        // failure (e.g. no Secret Service daemon on a headless Linux).
        let keystore = default_keystore();
        let mut password_from_keychain = false;
        if profile.password.is_none() {
            if let Some(user) = profile.user.as_deref() {
                match keystore.load(user) {
                    Ok(Some(pwd)) => {
                        tracing::info!("loaded password for {user} from OS keychain");
                        profile.password = Some(pwd);
                        password_from_keychain = true;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("keychain load failed for {user}: {e:#}");
                    }
                }
            }
        }

        // ---- locale: explicit profile.locale overrides OS detection;
        // unsupported codes fall back to base inside set_locale().  Must
        // happen BEFORE any UI render so the first paint already shows
        // translated strings.
        let os_locale_code = os_locale::detect();
        let active_locale = match profile.locale.as_deref() {
            Some(explicit) if i18n::is_supported(explicit) => explicit.to_string(),
            _ => match &os_locale_code {
                Some(code) if i18n::is_supported(code) => code.clone(),
                _ => i18n::BASE.to_string(),
            },
        };
        i18n::set_locale(&active_locale);

        // Augment egui's font tables with OS-installed fonts for the
        // active locale's script.  No-op for Latin / Cyrillic / Greek
        // (bundled fonts cover those); logs a warning for CJK / Arabic /
        // Devanagari / Thai / etc. when no OS font is installed.
        if let Err(e) = fonts::load_for_locale(&cc.egui_ctx, &active_locale) {
            tracing::warn!("font loader returned error: {e}");
        }

        // Detect OS appearance once (cached), then resolve through the
        // user's stored ThemeChoice (Auto / Dark / Light).
        let os_appearance = detect_appearance();
        let initial_choice = ThemeChoice::from_config_str(&profile.theme);
        let initial = initial_choice.resolve(os_appearance);
        cc.egui_ctx.set_visuals(visuals_for(initial));
        if os_appearance == Appearance::Unknown && initial_choice == ThemeChoice::Auto {
            tracing::info!("OS did not advertise a colour scheme; defaulting to dark");
        }

        let to_csv = profile.to.join(", ");
        let cc_csv = profile.cc.join(", ");
        let bcc_csv = profile.bcc.join(", ");

        Self {
            cfg_path,
            cfg,
            profile_name,
            profile,
            log_sink: sink,
            log_buf: Vec::new(),
            show_pwd: false,
            busy: false,
            result_rx: None,
            last_results: TestResults::default(),
            to_csv,
            cc_csv,
            bcc_csv,
            tab: Tab::Servers,
            diagnose_input: String::new(),
            diagnose_hints: Vec::new(),
            #[cfg(feature = "dns")]
            dns_domain: String::new(),
            #[cfg(feature = "dns")]
            dns_report: None,
            #[cfg(feature = "dns")]
            dns_hints: Vec::new(),
            #[cfg(feature = "dns")]
            dns_running: false,
            #[cfg(feature = "dns")]
            dns_rx: None,
            #[cfg(feature = "oauth")]
            oauth_login_running: false,
            #[cfg(feature = "oauth")]
            oauth_login_status: String::new(),
            #[cfg(feature = "oauth")]
            oauth_login_rx: None,
            os_appearance,
            os_locale_code,
            applied_appearance: initial,
            keystore,
            password_from_keychain,
        }
    }

    /// Re-apply the user's current theme preference if it produces a
    /// different concrete appearance than what we last applied.  Called
    /// once per frame; cheap no-op when nothing changed.
    fn refresh_theme(&mut self, ctx: &egui::Context) {
        let choice = ThemeChoice::from_config_str(&self.profile.theme);
        let target = choice.resolve(self.os_appearance);
        if target != self.applied_appearance {
            ctx.set_visuals(visuals_for(target));
            self.applied_appearance = target;
            tracing::info!(
                "theme: now {} (choice={}, os={:?})",
                target_label(target),
                choice.as_str(),
                self.os_appearance
            );
        }
    }

    /// Overwrite the SMTP / IMAP / POP3 host, port, and security fields
    /// on the active profile from a curated provider preset.  Leaves
    /// every other field (credentials, profile name, theme, ...) alone.
    /// Providers without POP3 (iCloud, Proton Bridge) disable the POP3
    /// test rather than leaving stale data behind.
    fn apply_provider(&mut self, p: &Provider) {
        self.profile.smtp_host = p.smtp.host.into();
        self.profile.smtp_port = p.smtp.port;
        self.profile.smtp_security = p.smtp.security;
        self.profile.imap_host = p.imap.host.into();
        self.profile.imap_port = p.imap.port;
        self.profile.imap_security = p.imap.security;
        match p.pop {
            Some(pop) => {
                self.profile.pop_host = pop.host.into();
                self.profile.pop_port = pop.port;
                self.profile.pop_security = pop.security;
                // Leave pop_enabled untouched; user may want POP off
                // even on providers that support it.
            }
            None => {
                self.profile.pop_enabled = false;
            }
        }
        tracing::info!("applied provider preset: {}", p.name);
    }

    fn run_tests_async(&mut self) {
        // Sync CSV fields back into profile.
        self.profile.to = csv_to_vec(&self.to_csv);
        self.profile.cc = csv_to_vec(&self.cc_csv);
        self.profile.bcc = csv_to_vec(&self.bcc_csv);

        let (tx, rx): (Sender<TestResults>, Receiver<TestResults>) = std::sync::mpsc::channel();
        self.result_rx = Some(rx);
        self.busy = true;
        let profile = self.profile.clone();
        thread::spawn(move || {
            let r = run_tests(&profile);
            let _ = tx.send(r);
        });
    }

    fn save_config(&mut self) -> anyhow::Result<()> {
        // sync CSVs first
        self.profile.to = csv_to_vec(&self.to_csv);
        self.profile.cc = csv_to_vec(&self.cc_csv);
        self.profile.bcc = csv_to_vec(&self.bcc_csv);

        // No credential handling here: Profile.password and .oauth_token
        // are `#[serde(skip)]` so they are dropped at serialise time
        // unconditionally.  See AGENTS.md rule #8.
        self.cfg
            .upsert_profile(&self.profile_name, self.profile.clone());
        self.cfg.active = self.profile_name.clone();
        let target = self.cfg_path.clone().unwrap_or_else(default_save_path);
        self.cfg.save(&target)?;
        self.cfg_path = Some(target);
        Ok(())
    }
}

fn csv_to_vec(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

impl eframe::App for App {
    // egui 0.34: `ui()` is the required entry; `update(ctx, frame)` is
    // deprecated and provided as a no-op default by the trait.
    fn ui(&mut self, root_ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root_ui.ctx().clone();
        // React to a theme change made on the Advanced tab the previous
        // frame.  No-op when the chosen theme already matches.
        self.refresh_theme(&ctx);
        // Drain log lines from the sink.
        self.log_sink.drain_into(&mut self.log_buf);
        if self.log_buf.len() > 5000 {
            let drop = self.log_buf.len() - 5000;
            self.log_buf.drain(..drop);
        }

        // Poll background test thread.
        if let Some(rx) = &self.result_rx {
            if let Ok(r) = rx.try_recv() {
                self.last_results = r;
                self.busy = false;
                self.result_rx = None;
            }
        }
        if self.busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }

        // ----- top bar ------------------------------------------------
        egui::Panel::top("top").show_inside(root_ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(t("ui.topbar.profile_label"));
                let names = self.cfg.profile_names();
                egui::ComboBox::from_id_salt("profile")
                    .selected_text(&self.profile_name)
                    .show_ui(ui, |ui| {
                        for n in &names {
                            if ui.selectable_label(&self.profile_name == n, n).clicked() {
                                self.profile_name = n.clone();
                                if let Some(p) = self.cfg.profile(n) {
                                    self.profile = p.clone();
                                    self.to_csv = self.profile.to.join(", ");
                                    self.cc_csv = self.profile.cc.join(", ");
                                    self.bcc_csv = self.profile.bcc.join(", ");
                                }
                            }
                        }
                    });
                if ui
                    .button(t("ui.topbar.save_config"))
                    .on_hover_text(t("ui.topbar.save_config_tooltip"))
                    .clicked()
                {
                    if let Err(e) = self.save_config() {
                        tracing::error!("save failed: {e:#}");
                    } else {
                        tracing::info!(
                            "Saved profile [{}] to {}",
                            self.profile_name,
                            self.cfg_path
                                .as_ref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_default()
                        );
                    }
                }
                // Provider preset menu: applies one curated set of
                // host/port/security values to all three protocol
                // blocks below.  Other fields (credentials, etc.) are
                // left alone.
                let mut chosen: Option<&'static Provider> = None;
                // "..." rather than a unicode arrow because the default
                // egui font ships without U+25BE (small down-pointing
                // triangle) and falls back to a tofu glyph.
                ui.menu_button(t("ui.topbar.provider_preset"), |ui| {
                    for p in providers::PROVIDERS {
                        let mut label = p.name.to_string();
                        if p.pop.is_none() {
                            label.push_str("  (no POP3)");
                        }
                        if ui.button(label).clicked() {
                            chosen = Some(p);
                            ui.close();
                        }
                    }
                });
                if let Some(p) = chosen {
                    self.apply_provider(p);
                    if let Some(note) = p.note {
                        tracing::info!("note: {note}");
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        self.cfg_path
                            .as_ref()
                            .map(|p| format!("{}", p.display()))
                            .unwrap_or_else(|| t("ui.topbar.config_path_none")),
                    );
                });
            });
        });

        // ----- bottom: action bar + summary ---------------------------
        egui::Panel::bottom("bottom").show_inside(root_ui, |ui| {
            ui.horizontal(|ui| {
                let run = ui.add_enabled(
                    !self.busy,
                    egui::Button::new(if self.busy {
                        t("ui.actions.running")
                    } else {
                        t("ui.actions.run_test")
                    }),
                );
                if run.clicked() {
                    self.run_tests_async();
                }
                ui.separator();
                outcome_chip(ui, "SMTP", self.last_results.smtp);
                outcome_chip(ui, "IMAP", self.last_results.imap);
                outcome_chip(ui, "POP3", self.last_results.pop3);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(t("ui.actions.clear_log")).clicked() {
                        self.log_buf.clear();
                    }
                });
            });
        });

        // ----- log panel along the bottom (own region, deterministic
        // height) so the tab content above never fights it for space.
        // egui 0.34: BottomPanel can have a fixed default + be resizable
        // by the user via the splitter at the top edge.
        egui::Panel::bottom("log")
            .resizable(true)
            .default_size(260.0)
            .min_size(120.0)
            .show_inside(root_ui, |ui| {
                ui.label(egui::RichText::new(t("ui.log.heading")).strong());
                egui::ScrollArea::vertical()
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for line in &self.log_buf {
                            let (color, tag) = level_style(line.level, ui.visuals().dark_mode);
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(tag).color(color).monospace());
                                ui.label(egui::RichText::new(&line.text).monospace());
                            });
                        }
                    });
            });

        // ----- main: tabs + tab content fills the remaining space ----
        // CentralPanel must be added AFTER all other panels per egui 0.34.
        egui::CentralPanel::default().show_inside(root_ui, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Servers, t("ui.tab.servers"));
                ui.selectable_value(&mut self.tab, Tab::Send, t("ui.tab.send_mail"));
                ui.selectable_value(&mut self.tab, Tab::Tls, t("ui.tab.tls_auth"));
                ui.selectable_value(&mut self.tab, Tab::Advanced, t("ui.tab.advanced"));
                ui.selectable_value(&mut self.tab, Tab::Diagnose, t("ui.tab.diagnose"));
                #[cfg(feature = "dns")]
                ui.selectable_value(&mut self.tab, Tab::Dns, t("ui.tab.dns"));
            });
            ui.separator();

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| match self.tab {
                    Tab::Servers => tab_servers(ui, self),
                    Tab::Send => tab_send(ui, self),
                    Tab::Tls => tab_tls(ui, self),
                    Tab::Advanced => tab_advanced(ui, self),
                    Tab::Diagnose => tab_diagnose(ui, self),
                    #[cfg(feature = "dns")]
                    Tab::Dns => tab_dns(ui, self),
                });
        });
    }
}

// -----------------------------------------------------------------------
// main
// -----------------------------------------------------------------------
fn main() -> eframe::Result<()> {
    let sink = Arc::new(LogSink::default());
    let layer = GuiLayer { sink: sink.clone() };
    // The GUI log panel shows user-relevant events.  Default to INFO so we
    // do not flood it with eframe/winit/glow internal trace lines; advanced
    // users can opt into DEBUG by setting RUST_LOG, e.g.:
    //   RUST_LOG=smtp_test_tool=debug smtp-test-tool-gui
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new("info,eframe=warn,winit=warn,wgpu_core=warn,naga=warn")
    });
    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
    // LevelFilter is still re-exported, keep the import so future tweaks
    // don't need a re-edit.
    let _keep = LevelFilter::INFO;

    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 760.0])
            .with_min_inner_size([720.0, 520.0])
            .with_title("SMTP Test Tool"),
        ..Default::default()
    };
    eframe::run_native(
        "SMTP Test Tool",
        opts,
        Box::new(|cc| Ok(Box::new(App::new(sink, cc)))),
    )
}
