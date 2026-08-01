//! §11.5 alerting.
//!
//! Alerting is the layer that actually terminates an attack; the counters merely
//! bound the damage while it fires. Route this somewhere readable while
//! travelling, and test that path.
//!
//! `BW_KEYD_ALERT_COMMAND` names a program run with the message as its single
//! argument. It is spawned detached and never waited on: a hanging alert hook
//! must not hold a database transaction or a client connection open.

use std::process::{Command, Stdio};

use crate::budget::LIFETIME_CEILING;
use crate::log;

const ALERT_ENV: &str = "BW_KEYD_ALERT_COMMAND";

/// `lifetime` crossing 80 % of the ceiling.
const CEILING_WARN_FRACTION: i64 = 80;

pub fn fire(message: &str) {
    log::warn(&format!("ALERT {message}"));

    let Ok(cmd) = std::env::var(ALERT_ENV) else {
        return;
    };
    if cmd.is_empty() {
        return;
    }
    let spawned = Command::new(&cmd)
        .arg(message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    if let Err(e) = spawned {
        log::error(&format!("alert command {cmd}: {e}"));
    }
}

/// Called on every granted evaluation.
pub fn check(device: &str, lifetime: i64) {
    let threshold = LIFETIME_CEILING * CEILING_WARN_FRACTION / 100;
    // fires once, on the crossing itself
    if lifetime == threshold {
        fire(&format!(
            "device {device} lifetime {lifetime} has crossed {CEILING_WARN_FRACTION}% of the {LIFETIME_CEILING} ceiling"
        ));
    }
}

/// Any `denied` is worth knowing about: a correctly configured device never
/// produces one.
pub fn denied(device: &str) {
    fire(&format!("denied request from device {device}"));
}

pub fn enrolled(device: &str, label: &str) {
    fire(&format!("enrollment token used by {device} ({label})"));
}

/// Rate thresholds from §6.2, evaluated against the audit log rather than the
/// database: `tokens` and `lifetime` alone cannot express "30 in the last 24 h".
/// `bw-keyctl list` shows the lifetime counter; this covers the burst case.
pub struct RateWindow {
    events: Vec<i64>,
}

impl RateWindow {
    pub const DAY_LIMIT: usize = 30;
    pub const WEEK_LIMIT: usize = 200;

    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Records a consumed attempt and returns an alert message if either
    /// threshold has just been crossed.
    pub fn record(&mut self, now: i64) -> Option<String> {
        self.events.push(now);
        self.events.retain(|t| now - t <= 7 * 86_400);

        let day = self.events.iter().filter(|t| now - *t <= 86_400).count();
        let week = self.events.len();

        if day == Self::DAY_LIMIT {
            return Some(format!("{day} attempts in 24 h"));
        }
        if week == Self::WEEK_LIMIT {
            return Some(format!("{week} attempts in 7 d"));
        }
        None
    }
}

impl Default for RateWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_daily_threshold_fires_once_on_crossing() {
        let mut w = RateWindow::new();
        let t = 1_700_000_000;
        for i in 0..RateWindow::DAY_LIMIT - 1 {
            assert!(w.record(t + i as i64).is_none());
        }
        assert!(w.record(t + 100).is_some());
        assert!(w.record(t + 101).is_none());
    }

    #[test]
    fn events_outside_the_window_are_forgotten() {
        let mut w = RateWindow::new();
        let t = 1_700_000_000;
        for i in 0..RateWindow::DAY_LIMIT - 1 {
            w.record(t + i as i64);
        }
        // two days later the old burst no longer counts
        assert!(w.record(t + 2 * 86_400).is_none());
    }
}

/// Per-device rate windows, shared across connection threads.
pub struct Rates {
    inner: std::sync::Mutex<std::collections::HashMap<String, RateWindow>>,
}

impl Rates {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn record(&self, device: &str, now: i64) {
        let crossed = {
            let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            map.entry(device.to_string())
                .or_default()
                .record(now)
        };
        if let Some(what) = crossed {
            fire(&format!("device {device}: {what}"));
        }
    }
}

impl Default for Rates {
    fn default() -> Self {
        Self::new()
    }
}
