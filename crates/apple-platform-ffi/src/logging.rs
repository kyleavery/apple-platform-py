//! Capture upstream `log` output into a bounded in-memory ring so callers can
//! drain it as JSON (`apple_platform_log_drain`) instead of losing it or
//! having it splatter onto stderr.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

use log::{LevelFilter, Log, Metadata, Record};
use serde::Serialize;

use crate::error::FfiError;

const RING_CAPACITY: usize = 1024;

#[derive(Serialize)]
struct LogEntry {
    level: String,
    target: String,
    message: String,
}

static RING: OnceLock<Mutex<VecDeque<LogEntry>>> = OnceLock::new();
static INSTALLED: OnceLock<()> = OnceLock::new();

fn ring() -> &'static Mutex<VecDeque<LogEntry>> {
    RING.get_or_init(|| Mutex::new(VecDeque::with_capacity(RING_CAPACITY)))
}

struct RingLogger;

impl Log for RingLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let Ok(mut ring) = ring().lock() else {
            return;
        };
        if ring.len() >= RING_CAPACITY {
            ring.pop_front();
        }
        ring.push_back(LogEntry {
            level: record.level().to_string(),
            target: record.target().to_string(),
            message: record.args().to_string(),
        });
    }

    fn flush(&self) {}
}

/// 0=off, 1=error, 2=warn, 3=info, 4=debug, 5=trace.
pub(crate) fn set_level(level: i32) -> Result<(), FfiError> {
    let filter = match level {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5 => LevelFilter::Trace,
        other => {
            return Err(FfiError::invalid_argument(format!(
                "log level must be 0..=5, got {other}"
            )))
        }
    };
    INSTALLED.get_or_init(|| {
        // Fails only if the host process already installed a global logger;
        // in that case records go there instead and the ring stays empty.
        let _ = log::set_boxed_logger(Box::new(RingLogger));
    });
    log::set_max_level(filter);
    Ok(())
}

/// Drain all buffered records as a JSON array (oldest first).
pub(crate) fn drain_json() -> Result<Vec<u8>, FfiError> {
    let entries: Vec<LogEntry> = match ring().lock() {
        Ok(mut ring) => ring.drain(..).collect(),
        Err(_) => Vec::new(),
    };
    Ok(serde_json::to_vec(&entries)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_level_and_drain() {
        set_level(4).unwrap();
        log::info!(target: "apple_platform_test", "hello from the ring");
        let drained: serde_json::Value = serde_json::from_slice(&drain_json().unwrap()).unwrap();
        let entries = drained.as_array().unwrap();
        assert!(entries
            .iter()
            .any(|e| e["message"] == "hello from the ring" && e["level"] == "INFO"));

        // Draining empties the ring.
        let again: serde_json::Value = serde_json::from_slice(&drain_json().unwrap()).unwrap();
        assert!(again.as_array().unwrap().is_empty());

        assert!(set_level(6).is_err());
    }
}
