
use std::io::Write;

fn ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn emit(level: &str, msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{} {level} {msg}", ts());
}

pub fn info(msg: &str) {
    emit("INFO", msg);
}

pub fn warn(msg: &str) {
    emit("WARN", msg);
}

pub fn error(msg: &str) {
    emit("ERROR", msg);
}

pub fn fatal(msg: &str) -> ! {
    emit("FATAL", msg);
    std::process::exit(1);
}

pub fn request(device: &str, outcome: &str, tokens: Option<f64>, lifetime: Option<i64>) {
    let tokens = tokens.map(|t| format!("{t:.2}")).unwrap_or_else(|| "-".into());
    let lifetime = lifetime.map(|l| l.to_string()).unwrap_or_else(|| "-".into());
    emit(
        "REQ",
        &format!("device={device} outcome={outcome} tokens={tokens} lifetime={lifetime}"),
    );
}
