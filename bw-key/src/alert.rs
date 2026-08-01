
use std::process::{Command, Stdio};

use crate::budget::LIFETIME_CEILING;
use crate::log;

const ALERT_ENV: &str = "BW_KEYD_ALERT_COMMAND";

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

pub fn check(device: &str, lifetime: i64) {
    let threshold = LIFETIME_CEILING * CEILING_WARN_FRACTION / 100;
    if lifetime == threshold {
        fire(&format!(
            "device {device} lifetime {lifetime} has crossed {CEILING_WARN_FRACTION}% of the {LIFETIME_CEILING} ceiling"
        ));
    }
}

pub fn denied(device: &str) {
    fire(&format!("denied request from device {device}"));
}

pub fn enrolled(device: &str, label: &str) {
    fire(&format!("enrollment token used by {device} ({label})"));
}

pub struct RateWindow {
    events: Vec<i64>,
}

impl RateWindow {
    pub const DAY_LIMIT: usize = 30;
    pub const WEEK_LIMIT: usize = 200;

    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

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
        assert!(w.record(t + 2 * 86_400).is_none());
    }
}

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
