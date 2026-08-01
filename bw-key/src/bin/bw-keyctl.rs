
use bw_key::{db, enroll, log, state};

use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bw-keyctl", about = "bw-keyd administration (local only)", version)]
struct Args {
    #[arg(long, global = true)]
    state: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    List,
    Enroll {
        #[arg(long)]
        label: String,
    },
    Revoke { device_id: String },
    Reset { device_id: String },
    Panic {
        #[arg(long)]
        yes: bool,
    },
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
    let server = store
        .with(|conn| db::get_meta(conn, db::META_LISTEN))?
        .unwrap_or_else(|| "<host:port>".into());
    println!("token (valid {} minutes, single use):", enroll::TOKEN_TTL_SECS / 60);
    println!();
    println!("  {token}");
    println!();
    println!("on the client:");
    println!("  bw-agent enroll --email <email> --server {server} --token {token}");
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

fn fmt_time(t: i64) -> String {
    let ago = db::now().saturating_sub(t);
    match ago {
        s if s < 60 => format!("{s}s ago"),
        s if s < 3600 => format!("{}m ago", s / 60),
        s if s < 86400 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}
