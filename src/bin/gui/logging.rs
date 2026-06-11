//! GUI log capture.
//!
//! A custom `tracing` [`Layer`] that buffers formatted records for the
//! log panel to render.  Thread-safe and fully decoupled from `App`.

use std::sync::{Arc, Mutex};
use tracing_subscriber::Layer;

#[derive(Clone, Copy, Debug)]
pub(crate) enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug)]
pub(crate) struct LogLine {
    pub(crate) level: LogLevel,
    pub(crate) text: String,
}

#[derive(Default)]
pub(crate) struct LogSink {
    lines: Mutex<Vec<LogLine>>,
}

impl LogSink {
    pub(crate) fn push(&self, level: LogLevel, text: String) {
        if let Ok(mut g) = self.lines.lock() {
            // Cap memory at 5000 lines so a long --wire run stays responsive.
            if g.len() > 5000 {
                g.drain(..1000);
            }
            g.push(LogLine { level, text });
        }
    }
    pub(crate) fn drain_into(&self, dst: &mut Vec<LogLine>) {
        if let Ok(mut g) = self.lines.lock() {
            dst.extend(g.drain(..));
        }
    }
}

pub(crate) struct GuiLayer {
    pub(crate) sink: Arc<LogSink>,
}

impl<S> Layer<S> for GuiLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldFmt::default();
        event.record(&mut visitor);
        let lvl = match *event.metadata().level() {
            tracing::Level::TRACE => LogLevel::Trace,
            tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::WARN => LogLevel::Warn,
            tracing::Level::ERROR => LogLevel::Error,
        };
        self.sink.push(lvl, visitor.message);
    }
}

#[derive(Default)]
struct FieldFmt {
    message: String,
}

impl tracing::field::Visit for FieldFmt {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
            // strip the surrounding quotes Debug puts on strings
            if self.message.starts_with('"') && self.message.ends_with('"') {
                self.message = self.message[1..self.message.len() - 1].to_string();
            }
        } else {
            self.message
                .push_str(&format!(" {}={value:?}", field.name()));
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.message.push_str(&format!(" {}={value}", field.name()));
        }
    }
}
