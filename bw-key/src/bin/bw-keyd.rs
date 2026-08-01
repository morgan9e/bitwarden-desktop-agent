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

    // `local_addr` rather than `args.bind`: it is what the kernel actually gave
    // us, so a hostname or an ephemeral port resolves to something pasteable.
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

/// Turns `--bind` into something `TcpListener` accepts, resolving an interface
/// name to its tailnet address.
///
/// Order matters: literal addresses are recognised before interface names so a
/// host can never shadow one, and anything left unrecognised is passed through
/// untouched, which keeps `--bind host.tailnet.ts.net:9797` resolving via DNS
/// exactly as it did before.
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
            // Not a port, so not a form we handle — e.g. a bare IPv6 literal.
            Err(_) => return Ok(spec.to_string()),
        },
        None => (spec, iface::DEFAULT_PORT),
    };

    match iface::tailnet_addr(name) {
        Ok(ip) => Ok(SocketAddr::new(ip, port).to_string()),
        // A hostname reaches here too, and DNS should get its turn. A bare name
        // with no port cannot be a `host:port`, so that one is a real failure.
        Err(e) if spec.contains(':') => {
            log::info(&format!("{name} is not an interface ({e}); trying as a host"));
            Ok(spec.to_string())
        }
        Err(e) => Err(e),
    }
}

/// §5.1: bind to the tailnet interface only. A wildcard bind exposes the one
/// component whose whole purpose is to be reachable only by enrolled devices.
fn reject_wildcard(bind: &str) {
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(bind);
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if matches!(host, "0.0.0.0" | "::" | "*" | "") {
        log::fatal(&format!(
            "refusing to bind {bind}: give the tailnet address explicitly"
        ));
    }
}
