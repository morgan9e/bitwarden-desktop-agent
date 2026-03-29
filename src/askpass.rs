use std::io::{self, BufRead, Write};
use std::process::Command;

pub type Prompter = Box<dyn Fn(&str) -> Option<String>>;

fn cli() -> Prompter {
    Box::new(|msg: &str| {
        eprint!("{msg} ");
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).ok()?;
        let trimmed = line.trim_end().to_string();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    })
}

fn osascript() -> Prompter {
    Box::new(|msg: &str| {
        let script = format!(
            "display dialog \"{}\" with title \"Bitwarden\" \
             default answer \"\" with hidden answer \
             buttons {{\"Cancel\",\"OK\"}} default button \"OK\"",
            msg
        );
        let out = Command::new("osascript").args(["-e", &script]).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        for part in stdout.trim().split(',') {
            if let Some(val) = part.trim().strip_prefix("text returned:") {
                let v = val.trim().to_string();
                return if v.is_empty() { None } else { Some(v) };
            }
        }
        None
    })
}

fn adw_askpass() -> Prompter {
    Box::new(|msg: &str| {
        let out = Command::new("adw-askpass")
            .args(["--password", "--title", "Bitwarden", "--text", msg])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    })
}

fn zenity() -> Prompter {
    Box::new(|msg: &str| {
        let out = Command::new("zenity")
            .args(["--entry", "--hide-text", "--title", "", "--text", msg, "--width", "300"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    })
}

fn kdialog() -> Prompter {
    Box::new(|msg: &str| {
        let out = Command::new("kdialog")
            .args(["--password", msg, "--title", "Bitwarden"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    })
}

fn ssh_askpass() -> Option<Prompter> {
    let binary = std::env::var("SSH_ASKPASS")
        .ok()
        .or_else(|| which("ssh-askpass"))?;
    Some(Box::new(move |msg: &str| {
        let out = Command::new(&binary).arg(msg).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(s) }
    }))
}

fn which(name: &str) -> Option<String> {
    std::env::var_os("PATH")?
        .to_str()?
        .split(':')
        .map(|dir| std::path::Path::new(dir).join(name))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
}

pub fn get_prompter(name: Option<&str>) -> Prompter {
    match name {
        Some("cli") => cli(),
        Some("osascript") => osascript(),
        Some("adw-askpass") => adw_askpass(),
        Some("zenity") => zenity(),
        Some("kdialog") => kdialog(),
        Some("ssh-askpass") => ssh_askpass().unwrap_or_else(|| {
            crate::log::fatal("SSH_ASKPASS not set and ssh-askpass not found")
        }),
        Some(other) => crate::log::fatal(&format!("unknown askpass provider: {other}")),
        None => {
            if cfg!(target_os = "macos") {
                return osascript();
            }
            if which("adw-askpass").is_some() {
                return adw_askpass();
            }
            if which("zenity").is_some() {
                return zenity();
            }
            if which("kdialog").is_some() {
                return kdialog();
            }
            cli()
        }
    }
}

#[allow(dead_code)]
pub fn available() -> Vec<&'static str> {
    let mut found = vec!["cli"];
    if cfg!(target_os = "macos") {
        found.push("osascript");
    }
    if which("adw-askpass").is_some() {
        found.push("adw-askpass");
    }
    if which("zenity").is_some() {
        found.push("zenity");
    }
    if which("kdialog").is_some() {
        found.push("kdialog");
    }
    if which("ssh-askpass").is_some() || std::env::var("SSH_ASKPASS").is_ok() {
        found.push("ssh-askpass");
    }
    found
}
