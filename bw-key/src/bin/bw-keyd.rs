use bw_key::{alert, db, log, server, state};

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::Parser;

use bw_proto::noise;

#[derive(Parser)]
#[command(name = "bw-keyd", about = "per-device key server for bw-agent", version)]
struct Args {
    /// Address to listen on. Must be a specific tailnet address, never 0.0.0.0.
    #[arg(long)]
    bind: String,

    /// State directory holding devices.db and server.key
    #[arg(long)]
    state: Option<PathBuf>,

    /// Print the server's static public key and exit
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

    reject_wildcard(&args.bind);

    let store = Arc::new(db::Db::open(&dir.join(state::DB_FILE)).unwrap_or_else(|e| log::fatal(&e)));
    let rates = Arc::new(alert::Rates::new());

    let listener = TcpListener::bind(&args.bind)
        .unwrap_or_else(|e| log::fatal(&format!("bind {}: {e}", args.bind)));
    log::info(&format!(
        "listening on {} (static {})",
        args.bind,
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
