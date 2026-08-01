use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const MAX_MSG: usize = 1024 * 1024;
const MAX_CONNS: usize = 16;

pub trait Handler {
    fn handle(&mut self, msg: serde_json::Value) -> Option<serde_json::Value>;
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred.uid)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Some(uid)
    } else {
        None
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_uid(_stream: &UnixStream) -> Option<u32> {
    None
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

pub fn serve<F, H>(sock_path: &Path, new_session: F)
where
    F: Fn() -> H + Send + Sync + 'static,
    H: Handler,
{
    if sock_path.exists() {
        std::fs::remove_file(sock_path).ok();
    }

    let prev_umask = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(sock_path);
    unsafe { libc::umask(prev_umask) };

    let listener = listener.unwrap_or_else(|e| {
        crate::log::fatal(&format!("bind failed: {e}"));
    });

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600)).ok();
    }

    ctrlc_cleanup(sock_path.to_path_buf());

    let own_uid = unsafe { libc::geteuid() };
    let live = Arc::new(AtomicUsize::new(0));
    let new_session = Arc::new(new_session);

    for stream in listener.incoming() {
        let mut conn = match stream {
            Ok(c) => c,
            Err(_) => break,
        };

        match peer_uid(&conn) {
            Some(uid) if uid == own_uid => {}
            Some(uid) => {
                crate::log::warn(&format!("rejected connection from uid {uid}"));
                continue;
            }
            None => {
                crate::log::warn("rejected connection: peer credentials unavailable");
                continue;
            }
        }

        if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNS {
            live.fetch_sub(1, Ordering::SeqCst);
            crate::log::warn("connection limit reached, dropping client");
            continue;
        }

        let live = live.clone();
        let new_session = new_session.clone();
        thread::spawn(move || {
            crate::log::info("client connected");
            let mut session = new_session();
            handle_conn(&mut conn, &mut session);
            crate::log::info("client disconnected");
            live.fetch_sub(1, Ordering::SeqCst);
        });
    }

    if sock_path.exists() {
        std::fs::remove_file(sock_path).ok();
    }
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

fn handle_conn<H: Handler>(conn: &mut UnixStream, session: &mut H) {
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

        if let Some(resp) = session.handle(msg) {
            send_message(conn, &resp);
        }
    }
}
