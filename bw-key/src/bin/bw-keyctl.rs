//! `bw-keyctl` — local admin CLI.
//!
//! Operates on the SQLite file directly, as the `bwkey` user on the server
//! host. WAL makes concurrent access with the running daemon safe, and it
//! avoids inventing a second network protocol whose only client is the operator.

use bw_key::{db, enroll, log, state};

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bw-keyctl", about = "bw-keyd administration (local only)", version)]
struct Args {
    /// State directory holding devices.db and server.key
    #[arg(long, global = true)]
    state: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// device_id, label, state, last_seen, budget
    List,
    /// Issue a single-use enrollment token, valid for 15 minutes
    Enroll {
        #[arg(long)]
        label: String,
    },
    /// Destroy this device's OPRF key. Irreversible.
    Revoke { device_id: String },
    /// Clear a device's lifetime counter
    Reset { device_id: String },
    /// Revoke every device
    Panic {
        /// Required: this cannot be undone
        #[arg(long)]
        yes: bool,
    },
    /// Print the server's static public key
    Pubkey,
}

fn main() {
    let args = Args::parse();
    let dir = args.state.unwrap_or_else(state::default_dir);
    state::ensure_dir(&dir).unwrap_or_else(|e| log::fatal(&e));
    let key = state::load_or_create_key(&dir).unwrap_or_else(|e| log::fatal(&e));

    if let Cmd::Pubkey = args.cmd {
        println!("{}", B64.encode(bw_proto::noise::public_key(&key)));
        return;
    }

    let store = db::Db::open(&dir.join(state::DB_FILE)).unwrap_or_else(|e| log::fatal(&e));

    let result = match args.cmd {
        Cmd::List => list(&store),
        Cmd::Enroll { label } => issue(&store, &key, &label),
        Cmd::Revoke { device_id } => revoke(&store, &device_id),
        Cmd::Reset { device_id } => reset(&store, &device_id),
        Cmd::Panic { yes } => panic_all(&store, yes),
        Cmd::Pubkey => unreachable!(),
    };

    if let Err(e) = result {
        log::fatal(&e);
    }
}

fn list(store: &db::Db) -> Result<(), String> {
    let rows = store.with(|conn| db::list(conn))?;
    if rows.is_empty() {
        println!("no devices");
        return Ok(());
    }
    println!(
        "{:<32}  {:<16}  {:<8}  {:<20}  {:>6}  {:>8}",
        "DEVICE_ID", "LABEL", "STATE", "LAST_SEEN", "TOKENS", "LIFETIME"
    );
    for r in rows {
        println!(
            "{:<32}  {:<16}  {:<8}  {:<20}  {:>6.2}  {:>8}",
            hex::encode(&r.device_id),
            truncate(&r.label, 16),
            r.state,
            r.last_seen.map(fmt_time).unwrap_or_else(|| "never".into()),
            r.tokens,
            r.lifetime
        );
    }
    Ok(())
}

fn issue(store: &db::Db, key: &[u8; 32], label: &str) -> Result<(), String> {
    let server_pub = bw_proto::noise::public_key(key);
    let token = store.with(|conn| enroll::issue_token(conn, server_pub, label))?;
    println!("token (valid {} minutes, single use):", enroll::TOKEN_TTL_SECS / 60);
    println!();
    println!("  {token}");
    println!();
    println!("on the client:");
    println!("  bw-agent enroll --email <email> --server <host:port> --token {token}");
    log::info(&format!("enrollment token issued for {label}"));
    Ok(())
}

fn revoke(store: &db::Db, prefix: &str) -> Result<(), String> {
    let id = store.with(|conn| {
        let id = db::find_by_prefix(conn, prefix)?;
        db::revoke(conn, &id)?;
        Ok(id)
    })?;
    println!("revoked {}", hex::encode(&id));
    println!("that device's blob is now permanently undecryptable; re-enroll to restore it");
    Ok(())
}

fn reset(store: &db::Db, prefix: &str) -> Result<(), String> {
    let id = store.with(|conn| {
        let id = db::find_by_prefix(conn, prefix)?;
        conn.execute(
            "UPDATE devices SET lifetime = 0 WHERE device_id = ?1",
            [id.as_slice()],
        )
        .map_err(|e| e.to_string())?;
        Ok(id)
    })?;
    println!("lifetime counter cleared for {}", hex::encode(&id));
    Ok(())
}

fn panic_all(store: &db::Db, confirmed: bool) -> Result<(), String> {
    if !confirmed {
        return Err("this revokes every device irreversibly; pass --yes".into());
    }
    let ids = store.with(|conn| {
        let ids: Vec<Vec<u8>> = db::list(conn)?
            .into_iter()
            .filter(|d| d.state != db::STATE_REVOKED)
            .map(|d| d.device_id)
            .collect();
        for id in &ids {
            db::revoke(conn, id)?;
        }
        Ok(ids)
    })?;
    println!("revoked {} device(s)", ids.len());
    Ok(())
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n - 1).chain("…".chars()).collect()
    }
}

/// Unix seconds, rendered without pulling in a date library: the operator reads
/// these next to `journalctl` output, which stamps its own wall-clock time.
fn fmt_time(t: i64) -> String {
    let ago = db::now().saturating_sub(t);
    match ago {
        s if s < 60 => format!("{s}s ago"),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}
