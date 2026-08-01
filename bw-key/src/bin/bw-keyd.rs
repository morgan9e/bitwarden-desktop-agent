use bw_key::{alert, db, iface, log, server, state};

use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;

use bw_proto::noise;

#[derive(Parser)]
#[command(name = "bw-keyd", about = "per-device key server for bw-agent", version)]
struct Args {
    #[arg(long, default_value = iface::DEFAULT_IFACE)]
    bind: String,

    #[arg(long)]
    state: Option<PathBuf>,

    #[arg(long)]
    print_pubkey: bool,
}

fn main() {
    let args = Args::parse();
    let dir = args.state.unwrap_or_else(state::default_dir);
    state::ensure_dir(&dir).unwrap_or_else(|e| log::fatal(&e));

    let key = state::load_or_create_key(&dir).unwrap_or_else(|e| log::fatal(&e));
    let pubkey = noise::public_key(&key);

    if args.print_pubkey {
        println!("{}", B64.encode(pubkey));
        return;
    }

    let bind = resolve(&args.bind).unwrap_or_else(|e| log::fatal(&e));
    reject_wildcard(&bind);

    let store = Arc::new(db::Db::open(&dir.join(state::DB_FILE)).unwrap_or_else(|e| log::fatal(&e)));
    let rates = Arc::new(alert::Rates::new());

    let listener =
        TcpListener::bind(&bind).unwrap_or_else(|e| log::fatal(&format!("bind {bind}: {e}")));

    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| args.bind.clone());
    if let Err(e) = store.with(|conn| db::set_meta(conn, db::META_LISTEN, &addr)) {
        log::warn(&format!("could not publish listen address: {e}"));
    }

    log::info(&format!(
        "listening on {addr} (static {})",
        B64.encode(pubkey)
    ));

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let store = store.clone();
        let rates = rates.clone();
        std::thread::spawn(move || {
            if let Err(e) = server::handle(stream, &store, &key, &rates) {
                log::warn(&format!("connection: {e}"));
            }
        });
    }
}

fn resolve(spec: &str) -> Result<String, String> {
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok(addr.to_string());
    }
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, iface::DEFAULT_PORT).to_string());
    }

    let (name, port) = match spec.rsplit_once(':') {
        Some((name, port)) => match port.parse::<u16>() {
            Ok(p) => (name, p),
            Err(_) => return Ok(spec.to_string()),
        },
        None => (spec, iface::DEFAULT_PORT),
    };

    match iface::tailnet_addr(name) {
        Ok(ip) => Ok(SocketAddr::new(ip, port).to_string()),
        Err(e) if spec.contains(':') => {
            log::info(&format!("{name} is not an interface ({e}); trying as a host"));
            Ok(spec.to_string())
        }
        Err(e) => Err(e),
    }
}

fn reject_wildcard(bind: &str) {
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if matches!(host, "0.0.0.0" | "::" | "*" | "") {
        log::fatal(&format!(
            "refusing to bind {bind}: give the tailnet address explicitly"
        ));
    }
}
