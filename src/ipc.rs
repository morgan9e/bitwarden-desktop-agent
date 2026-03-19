use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

const MAX_MSG: usize = 1024 * 1024;

pub fn socket_path() -> PathBuf {
    let cache = dirs_cache().join("com.bitwarden.desktop");
    std::fs::create_dir_all(&cache).ok();
    cache.join("s.bw")
}

fn dirs_cache() -> PathBuf {
    dirs_home().join(".cache")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn recv_exact(stream: &mut UnixStream, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut pos = 0;
    while pos < n {
        match stream.read(&mut buf[pos..]) {
            Ok(0) => return None,
            Ok(k) => pos += k,
            Err(_) => return None,
        }
    }
    Some(buf)
}

pub fn read_message(stream: &mut UnixStream) -> Option<serde_json::Value> {
    let header = recv_exact(stream, 4)?;
    let length = u32::from_ne_bytes(header[..4].try_into().ok()?) as usize;
    if length == 0 || length > MAX_MSG {
        return None;
    }
    let data = recv_exact(stream, length)?;
    serde_json::from_slice(&data).ok()
}

pub fn send_message(stream: &mut UnixStream, msg: &serde_json::Value) {
    let data = serde_json::to_vec(msg).unwrap();
    let len_bytes = (data.len() as u32).to_ne_bytes();
    let _ = stream.write_all(&len_bytes);
    let _ = stream.write_all(&data);
}

pub fn serve<F>(sock_path: &Path, mut handler: F)
where
    F: FnMut(serde_json::Value) -> Option<serde_json::Value>,
{
    if sock_path.exists() {
        std::fs::remove_file(sock_path).ok();
    }

    let listener = UnixListener::bind(sock_path).unwrap_or_else(|e| {
        crate::log::fatal(&format!("bind failed: {e}"));
    });

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600)).ok();
    }

    let cleanup = || {
        if sock_path.exists() {
            std::fs::remove_file(sock_path).ok();
        }
    };

    ctrlc_cleanup(sock_path.to_path_buf());

    for stream in listener.incoming() {
        match stream {
            Ok(mut conn) => {
                crate::log::info("client connected");
                handle_conn(&mut conn, &mut handler);
                crate::log::info("client disconnected");
            }
            Err(_) => break,
        }
    }

    cleanup();
}

fn ctrlc_cleanup(path: PathBuf) {
    ctrlc::set_handler(move || {
        if path.exists() {
            std::fs::remove_file(&path).ok();
        }
        std::process::exit(0);
    })
    .ok();
}

fn handle_conn<F>(conn: &mut UnixStream, handler: &mut F)
where
    F: FnMut(serde_json::Value) -> Option<serde_json::Value>,
{
    loop {
        let msg = match read_message(conn) {
            Some(m) => m,
            None => break,
        };

        if msg.get("command").is_some() && msg.get("appId").is_none() {
            if let Some(cmd) = msg.get("command").and_then(|c| c.as_str()) {
                crate::log::info(&format!("proxy: {cmd}"));
            }
            continue;
        }

        if let Some(resp) = handler(msg) {
            send_message(conn, &resp);
        }
    }
}
