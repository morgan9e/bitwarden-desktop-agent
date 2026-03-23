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
    email: Option<String>,

    #[arg(long)]
    password: Option<String>,

    #[arg(long, default_value = "https://vault.bitwarden.com")]
    server: String,

    #[cfg_attr(target_os = "linux", arg(long, help = "Key storage backend [pin, tpm2]"))]
    #[cfg_attr(not(target_os = "linux"), arg(long, help = "Key storage backend [pin]"))]
    backend: Option<String>,

    #[arg(long)]
    askpass: Option<String>,

    #[arg(long)]
    enroll: bool,

    #[arg(long)]
    remove: bool,

    #[arg(long)]
    change_pin: bool,
}

fn user_hash(email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(email.to_lowercase().trim().as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

fn main() {
    let args = Args::parse();
    let store = get_backend(args.backend.as_deref());
    let prompt = get_prompter(args.askpass.as_deref());
    log::info(&format!("backend: {}", store.name()));

    if args.enroll {
        let email = args
            .email
            .as_deref()
            .unwrap_or_else(|| log::fatal("--email required for enrollment"));
        let uid = user_hash(email);

        log::info(if !store.has_key(&uid) {
            "enrolling"
        } else {
            "re-enrolling"
        });

        let mut pw = args
            .password
            .clone()
            .or_else(|| prompt("master password:"))
            .unwrap_or_else(|| log::fatal("no password provided"));

        log::info(&format!("logging in as {email}"));
        let (mut key_bytes, server_uid) = auth::login(email, &pw, &args.server, &prompt);
        pw.zeroize();
        log::info(&format!("authenticated, uid={server_uid}"));

        let mut auth = prompt(&format!("choose {} password:", store.name()))
            .unwrap_or_else(|| log::fatal("no password provided"));
        let mut auth2 = prompt(&format!("confirm {} password:", store.name()))
            .unwrap_or_else(|| log::fatal("no password provided"));
        if auth != auth2 {
            auth.zeroize();
            auth2.zeroize();
            log::fatal("passwords don't match");
        }
        auth2.zeroize();

        store
            .store(&uid, &key_bytes, &auth)
            .unwrap_or_else(|e| log::fatal(&format!("store failed: {e}")));
        auth.zeroize();
        key_bytes.zeroize();
        log::info(&format!("key sealed via {}", store.name()));
        return;
    }

    if args.change_pin {
        let uid = match store.find_key() {
            Some(uid) => uid,
            None => log::fatal("no enrolled key found"),
        };

        let mut old_pw = prompt(&format!("current {} password:", store.name()))
            .unwrap_or_else(|| log::fatal("no password provided"));
        let mut data = store
            .load(&uid, &old_pw)
            .unwrap_or_else(|e| log::fatal(&format!("unseal failed: {e}")));
        old_pw.zeroize();

        let mut new_pw = prompt(&format!("new {} password:", store.name()))
            .unwrap_or_else(|| log::fatal("no password provided"));
        let mut new_pw2 = prompt(&format!("confirm {} password:", store.name()))
            .unwrap_or_else(|| log::fatal("no password provided"));
        if new_pw != new_pw2 {
            new_pw.zeroize();
            new_pw2.zeroize();
            data.zeroize();
            log::fatal("passwords don't match");
        }
        new_pw2.zeroize();

        store
            .store(&uid, &data, &new_pw)
            .unwrap_or_else(|e| log::fatal(&format!("seal failed: {e}")));
        new_pw.zeroize();
        data.zeroize();
        log::info("password changed");
        return;
    }

    if args.remove {
        let email = args
            .email
            .as_deref()
            .unwrap_or_else(|| log::fatal("--email required for --remove"));
        let uid = user_hash(email);
        if store.has_key(&uid) {
            store.remove(&uid);
            log::info(&format!("key removed for {email}"));
        } else {
            log::info(&format!("no key found for {email}"));
        }
        return;
    }

    let uid = match store.find_key() {
        Some(uid) => {
            log::info(&format!("found key: {uid}"));
            uid
        }
        None => log::fatal("no enrolled key found (run with --email <email> --enroll first)"),
    };

    let mut bridge = BiometricBridge::new(store, uid, prompt);
    let sock = ipc::socket_path();
    log::info(&format!("listening on {}", sock.display()));
    ipc::serve(&sock, |msg| bridge.handle(msg));
}
