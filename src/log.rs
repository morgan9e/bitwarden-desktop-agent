use std::sync::OnceLock;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();

fn ts() -> f64 {
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_secs_f64()
}

pub fn info(msg: &str) {
    eprintln!("[{:8.3}] {msg}", ts());
}

pub fn warn(msg: &str) {
    eprintln!("[{:8.3}] WARN {msg}", ts());
}

pub fn error(msg: &str) {
    eprintln!("[{:8.3}] ERROR {msg}", ts());
}

pub fn fatal(msg: &str) -> ! {
    error(msg);
    std::process::exit(1);
}
