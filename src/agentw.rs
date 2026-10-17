//! Windows logon launcher: runs bw-agent.exe with no console window, appends
//! its output to agent.log in the state directory, and restarts it if it
//! fails — the counterpart of the launchd plist and systemd unit.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    use std::fs::{File, OpenOptions};
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const MAX_LOG: u64 = 1024 * 1024;
    const RESTART_DELAY: Duration = Duration::from_secs(5);
    const FAILURE_WINDOW: Duration = Duration::from_secs(60);
    const MAX_FAILURES: usize = 5;

    let Ok(exe) = std::env::current_exe() else { return };
    let agent = exe.with_file_name("bw-agent.exe");
    let args: Vec<String> = std::env::args().skip(1).collect();

    let Ok(dir) = bw_proto::paths::ensure_state_dir() else { return };
    let log_path = dir.join("agent.log");
    if std::fs::metadata(&log_path).map(|m| m.len() > MAX_LOG).unwrap_or(false) {
        std::fs::rename(&log_path, dir.join("agent.log.old")).ok();
    }
    let open_log = || -> Option<File> {
        OpenOptions::new().create(true).append(true).open(&log_path).ok()
    };

    let mut failures: Vec<Instant> = Vec::new();
    loop {
        let (Some(out), Some(err)) = (open_log(), open_log()) else { return };
        let status = Command::new(&agent)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .creation_flags(CREATE_NO_WINDOW)
            .status();

        match status {
            Ok(s) if s.success() => return,
            _ => {
                let now = Instant::now();
                failures.retain(|t| now.duration_since(*t) < FAILURE_WINDOW);
                failures.push(now);
                if failures.len() >= MAX_FAILURES {
                    return;
                }
                std::thread::sleep(RESTART_DELAY);
            }
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("bw-agentw is only used on Windows; run bw-agent directly");
    std::process::exit(1);
}
