//! Theme visuals and semantic status colours for the GUI.
//!
//! All colours that carry information are verified against the egui
//! panel background to meet WCAG 2.2 AAA (>= 7:1) in both themes by the
//! tests at the bottom of this file.  No coupling to `App`.

use super::logging::LogLevel;
use eframe::egui;
use smtp_test_tool::i18n::{t, t_with};
use smtp_test_tool::runner::TestOutcome;
use smtp_test_tool::theme::{Appearance, ThemeChoice};

pub(crate) fn visuals_for(a: Appearance) -> egui::Visuals {
    match a {
        Appearance::Light => egui::Visuals::light(),
        // Both Dark and (defensively) Unknown map to dark, matching the
        // documented fallback in ThemeChoice::resolve.
        Appearance::Dark | Appearance::Unknown => egui::Visuals::dark(),
    }
}

pub(crate) fn target_label(a: Appearance) -> &'static str {
    match a {
        Appearance::Dark => "dark",
        Appearance::Light => "light",
        Appearance::Unknown => "dark (fallback)",
    }
}

/// Show the resolved OS hint next to 'Follow OS' so the user knows
/// what Auto currently maps to.
pub(crate) fn theme_label(choice: ThemeChoice, os: Appearance) -> String {
    match choice {
        ThemeChoice::Auto => t_with("ui.advanced.theme_follow_os", &[("hint", target_label(os))]),
        ThemeChoice::Dark => t("ui.advanced.theme_dark"),
        ThemeChoice::Light => t("ui.advanced.theme_light"),
    }
}

// Semantic status colours.  A single colour cannot clear WCAG 2.2 AAA
// (>= 7:1) against BOTH a near-black and a near-white panel, so these
// are theme-aware.  Every value is verified against the egui panel
// background by `tests::status_chip_colors_meet_wcag_aaa` (and the log
// variants by `tests::log_level_colors_meet_wcag_aaa`) below - changing
// one without keeping >= 7:1 is a build failure.
pub(crate) fn status_pass(dark: bool) -> egui::Color32 {
    if dark {
        egui::Color32::from_rgb(0x4a, 0xc2, 0x6b)
    } else {
        egui::Color32::from_rgb(0x0b, 0x5d, 0x0b)
    }
}
pub(crate) fn status_fail(dark: bool) -> egui::Color32 {
    if dark {
        egui::Color32::from_rgb(0xff, 0x94, 0x94)
    } else {
        egui::Color32::from_rgb(0x96, 0x00, 0x00)
    }
}
/// Neutral colour for skipped / idle / trace / debug.  Carries no
/// severity meaning on its own (the text label always does too, per
/// AGENTS.md §1.3 "colour is never the only signal"), but is still held
/// to AAA so the text stays comfortably legible.
pub(crate) fn status_muted(dark: bool) -> egui::Color32 {
    if dark {
        egui::Color32::from_rgb(0xb0, 0xb0, 0xb0)
    } else {
        egui::Color32::from_rgb(0x50, 0x50, 0x50)
    }
}

pub(crate) fn outcome_chip(ui: &mut egui::Ui, name: &str, o: Option<TestOutcome>) {
    // `name` is the protocol token used both as a stable display label
    // and as the suffix in localisation keys ('smtp', 'imap', 'pop3').
    let key_suffix = name.to_ascii_lowercase();
    let dark = ui.visuals().dark_mode;
    let (txt, col) = match o {
        Some(TestOutcome::Pass) => (
            t(&format!("ui.status.{key_suffix}_pass")),
            status_pass(dark),
        ),
        Some(TestOutcome::Fail) => (
            t(&format!("ui.status.{key_suffix}_fail")),
            status_fail(dark),
        ),
        Some(TestOutcome::Skipped) => (
            t(&format!("ui.status.{key_suffix}_skip")),
            status_muted(dark),
        ),
        None => (
            t(&format!("ui.status.{key_suffix}_idle")),
            status_muted(dark),
        ),
    };
    ui.label(egui::RichText::new(txt).color(col).monospace());
}

pub(crate) fn level_style(lvl: LogLevel, dark: bool) -> (egui::Color32, &'static str) {
    if dark {
        match lvl {
            LogLevel::Trace => (status_muted(true), "[TRACE]"),
            LogLevel::Debug => (status_muted(true), "[DEBUG]"),
            LogLevel::Info => (egui::Color32::from_rgb(0xf0, 0xf0, 0xf0), "[INFO ]"),
            LogLevel::Warn => (egui::Color32::from_rgb(0xff, 0xd1, 0x66), "[WARN ]"),
            LogLevel::Error => (status_fail(true), "[ERROR]"),
        }
    } else {
        match lvl {
            LogLevel::Trace => (status_muted(false), "[TRACE]"),
            LogLevel::Debug => (status_muted(false), "[DEBUG]"),
            LogLevel::Info => (egui::Color32::from_rgb(0x11, 0x11, 0x11), "[INFO ]"),
            LogLevel::Warn => (egui::Color32::from_rgb(0x7a, 0x42, 0x00), "[WARN ]"),
            LogLevel::Error => (status_fail(false), "[ERROR]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{level_style, status_fail, status_muted, status_pass, LogLevel};
    use eframe::egui;

    /// WCAG 2.2 relative luminance of an sRGB colour (0.0 ..= 1.0).
    fn rel_lum(c: egui::Color32) -> f64 {
        fn lin(ch: u8) -> f64 {
            let cs = ch as f64 / 255.0;
            if cs <= 0.03928 {
                cs / 12.92
            } else {
                ((cs + 0.055) / 1.055).powf(2.4)
            }
        }
        0.2126 * lin(c.r()) + 0.7152 * lin(c.g()) + 0.0722 * lin(c.b())
    }

    /// WCAG contrast ratio between two colours (1.0 ..= 21.0).
    fn contrast(a: egui::Color32, b: egui::Color32) -> f64 {
        let (l1, l2) = (rel_lum(a), rel_lum(b));
        let (hi, lo) = if l1 > l2 { (l1, l2) } else { (l2, l1) };
        (hi + 0.05) / (lo + 0.05)
    }

    // AGENTS.md §1.3 / §3: every element where colour carries information
    // MUST meet WCAG 2.2 Level AAA.  Our status / log text is
    // default-size monospace - "normal" text - so the bar is 7:1, not
    // the 4.5:1 large-text allowance.
    const AAA_NORMAL_TEXT: f64 = 7.0;

    /// The background these labels are actually drawn over: egui fills
    /// both the action bar and the log panel with `panel_fill`.  Read it
    /// from egui rather than hard-coding, so a future egui bump that
    /// changes the default is caught here instead of shipping silently.
    fn panel_bg(dark: bool) -> egui::Color32 {
        if dark {
            egui::Visuals::dark().panel_fill
        } else {
            egui::Visuals::light().panel_fill
        }
    }

    #[test]
    fn status_chip_colors_meet_wcag_aaa() {
        for dark in [true, false] {
            let bg = panel_bg(dark);
            let theme = if dark { "dark" } else { "light" };
            for (name, col) in [
                ("pass", status_pass(dark)),
                ("fail", status_fail(dark)),
                ("muted/skip/idle", status_muted(dark)),
            ] {
                let c = contrast(col, bg);
                assert!(
                    c >= AAA_NORMAL_TEXT,
                    "status chip '{name}' contrast {c:.2}:1 is below the {AAA_NORMAL_TEXT}:1 \
                     AAA bar on the {theme} panel"
                );
            }
        }
    }

    #[test]
    fn log_level_colors_meet_wcag_aaa() {
        for dark in [true, false] {
            let bg = panel_bg(dark);
            let theme = if dark { "dark" } else { "light" };
            for lvl in [
                LogLevel::Trace,
                LogLevel::Debug,
                LogLevel::Info,
                LogLevel::Warn,
                LogLevel::Error,
            ] {
                let (col, tag) = level_style(lvl, dark);
                let c = contrast(col, bg);
                assert!(
                    c >= AAA_NORMAL_TEXT,
                    "log level {tag} contrast {c:.2}:1 is below the {AAA_NORMAL_TEXT}:1 \
                     AAA bar on the {theme} panel"
                );
            }
        }
    }
}
