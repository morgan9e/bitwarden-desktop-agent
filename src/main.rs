mod askpass;
mod auth;
mod bridge;
mod crypto;
mod ipc;
mod log;
mod storage;

use clap::Parser;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use askpass::get_prompter;
use bridge::BiometricBridge;
use storage::get_backend;

#[derive(Parser)]
#[command(about = "Bitwarden desktop bridge agent")]
struct Args {
    #[arg(long)]
    email: String,

    #[arg(long)]
    password: Option<String>,

    #[arg(long, default_value = "https://vault.bitwarden.com")]
    server: String,

    #[arg(long)]
    backend: Option<String>,

    #[arg(long)]
    askpass: Option<String>,

    #[arg(long)]
    enroll: bool,

    #[arg(long)]
    remove: bool,
}

fn user_hash(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.to_lowercase().trim().as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn main() {
    let args = Args::parse();
    let uid = user_hash(&args.email);
    let store = get_backend(args.backend.as_deref());
    let prompt = get_prompter(args.askpass.as_deref());
    log::info(&format!("backend: {}", store.name()));

    if args.remove {
        if store.has_key(&uid) {
            store.remove(&uid);
            log::info(&format!("key removed for {}", args.email));
        } else {
            log::info(&format!("no key found for {}", args.email));
        }
        return;
    }

    if !store.has_key(&uid) || args.enroll {
        log::info(if !store.has_key(&uid) {
            "enrolling"
        } else {
            "re-enrolling"
        });

        let pw = args
            .password
            .clone()
            .or_else(|| prompt("master password:"))
            .unwrap_or_else(|| log::fatal("no password provided"));

        log::info(&format!("logging in as {}", args.email));
        let (mut key_bytes, server_uid) = auth::login(&args.email, &pw, &args.server, &prompt);
        log::info(&format!("authenticated, uid={server_uid}"));

        let auth = prompt(&format!("choose {} password:", store.name()))
            .unwrap_or_else(|| log::fatal("no password provided"));
        let auth2 = prompt(&format!("confirm {} password:", store.name()))
            .unwrap_or_else(|| log::fatal("no password provided"));
        if auth != auth2 {
            log::fatal("passwords don't match");
        }

        store
            .store(&uid, &key_bytes, &auth)
            .unwrap_or_else(|e| log::fatal(&format!("store failed: {e}")));
        key_bytes.zeroize();
        log::info(&format!("key sealed via {}", store.name()));
        log::info("wiped key from memory");
    } else {
        log::info(&format!("key ready for {}", args.email));
    }

    let mut bridge = BiometricBridge::new(store, uid, prompt);
    let sock = ipc::socket_path();
    log::info(&format!("listening on {}", sock.display()));
    ipc::serve(&sock, |msg| bridge.handle(msg));
}
