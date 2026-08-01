mod askpass;
mod auth;
mod blob;
mod bridge;
mod crypto;
mod device;
mod enroll;
mod ipc;
mod kdf;
mod log;
mod net;
mod unlock;

use std::sync::Arc;

use clap::{Parser, Subcommand};

use askpass::get_prompter;
use bridge::{Bridge, Session};
use device::Device;
use unlock::Unlocker;

#[derive(Parser)]
#[command(about = "Bitwarden desktop bridge agent", version)]
struct Args {
    #[arg(long, global = true)]
    askpass: Option<String>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    Enroll {
        #[arg(long)]
        email: String,
        #[arg(long, default_value = "https://vault.bitwarden.com")]
        vault: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value = "desktop")]
        label: String,
        #[arg(long, requires = "token")]
        server: Option<String>,
        #[arg(long, requires = "server")]
        token: Option<String>,
    },
    ChangePin,
    Remove,
    Status,
}

fn main() {
    let args = Args::parse();
    let prompt = get_prompter(args.askpass.as_deref());

    match args.cmd {
        Some(Cmd::Enroll {
            email,
            vault,
            password,
            label,
            server,
            token,
        }) => {
            let server = match (server, token) {
                (Some(addr), Some(token)) => Some(enroll::ServerEnrollment { addr, token }),
                _ => None,
            };
            enroll::enroll(&email, &vault, password, &label, server, &prompt)
                .unwrap_or_else(|e| log::fatal(&format!("enroll failed: {e}")));
        }
        Some(Cmd::ChangePin) => {
            enroll::change_pin(&prompt)
                .unwrap_or_else(|e| log::fatal(&format!("change-pin failed: {e}")));
        }
        Some(Cmd::Remove) => {
            enroll::remove().unwrap_or_else(|e| log::fatal(&format!("remove failed: {e}")));
        }
        Some(Cmd::Status) => enroll::status(),
        None => serve(prompt),
    }
}

fn serve(prompt: askpass::Prompter) {
    bw_proto::paths::ensure_state_dir()
        .unwrap_or_else(|e| log::fatal(&format!("state directory: {e}")));

    let device = Device::load(&bw_proto::paths::device_path())
        .unwrap_or_else(|_| log::fatal("not enrolled — run `bw-agent enroll --email <email>`"));
    if !blob::exists(&bw_proto::paths::blob_path()) {
        log::fatal("not enrolled — run `bw-agent enroll --email <email>`");
    }
    log::info(&format!("device {} ({})", device.device_id, device.email));

    let bridge = Arc::new(Bridge::new(Unlocker::new(device, prompt)));
    let sock = bw_proto::paths::socket_path();
    log::info(&format!("listening on {}", sock.display()));
    ipc::serve(&sock, move || Session::new(bridge.clone()));
}
