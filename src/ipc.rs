use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const MAX_MSG: usize = 1024 * 1024;
const MAX_CONNS: usize = 16;

pub trait Handler {
    fn handle(&mut self, msg: serde_json::Value) -> Option<serde_json::Value>;
}

#[cfg(unix)]
mod sys {
    use std::io;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;

    pub type Conn = UnixStream;

    pub fn endpoint() -> String {
        bw_proto::paths::socket_path().display().to_string()
    }

    pub struct Listener {
        inner: UnixListener,
        path: PathBuf,
        own_uid: u32,
    }

    impl Listener {
        pub fn bind() -> io::Result<Self> {
            let path = bw_proto::paths::socket_path();
            if path.exists() {
                std::fs::remove_file(&path).ok();
            }

            let prev_umask = unsafe { libc::umask(0o177) };
            let inner = UnixListener::bind(&path);
            unsafe { libc::umask(prev_umask) };
            let inner = inner?;

            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();

            ctrlc_cleanup(path.clone());
            Ok(Self {
                inner,
                path,
                own_uid: unsafe { libc::geteuid() },
            })
        }

        pub fn accept(&mut self) -> io::Result<Option<Conn>> {
            let (conn, _) = self.inner.accept()?;
            match peer_uid(&conn) {
                Some(uid) if uid == self.own_uid => Ok(Some(conn)),
                Some(uid) => {
                    crate::log::warn(&format!("rejected connection from uid {uid}"));
                    Ok(None)
                }
                None => {
                    crate::log::warn("rejected connection: peer credentials unavailable");
                    Ok(None)
                }
            }
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            std::fs::remove_file(&self.path).ok();
        }
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

    fn ctrlc_cleanup(path: PathBuf) {
        ctrlc::set_handler(move || {
            if path.exists() {
                std::fs::remove_file(&path).ok();
            }
            std::process::exit(0);
        })
        .ok();
    }
}

#[cfg(windows)]
mod sys {
    use std::io;

    use crate::winpipe;

    pub type Conn = std::fs::File;

    pub fn endpoint() -> String {
        bw_proto::paths::pipe_name()
    }

    pub struct Listener(winpipe::Listener);

    impl Listener {
        pub fn bind() -> io::Result<Self> {
            winpipe::Listener::bind(&endpoint()).map(Self).map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    io::Error::new(e.kind(), format!("{e} — is another bw-agent already running?"))
                } else {
                    e
                }
            })
        }

        pub fn accept(&mut self) -> io::Result<Option<Conn>> {
            let (conn, same_user) = self.0.accept()?;
            if !same_user {
                crate::log::warn("rejected connection from a process running as another user");
                return Ok(None);
            }
            Ok(Some(conn))
        }
    }
}

pub use sys::endpoint;

pub fn read_message<R: Read>(stream: &mut R) -> Option<serde_json::Value> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).ok()?;
    let length = u32::from_ne_bytes(header) as usize;
    if length == 0 || length > MAX_MSG {
        return None;
    }
    let mut data = vec![0u8; length];
    stream.read_exact(&mut data).ok()?;
    serde_json::from_slice(&data).ok()
}

pub fn send_message<W: Write>(stream: &mut W, msg: &serde_json::Value) {
    let data = serde_json::to_vec(msg).unwrap();
    let len_bytes = (data.len() as u32).to_ne_bytes();
    let _ = stream.write_all(&len_bytes);
    let _ = stream.write_all(&data);
    let _ = stream.flush();
}

pub fn serve<F, H>(new_session: F)
where
    F: Fn() -> H + Send + Sync + 'static,
    H: Handler,
{
    let mut listener = sys::Listener::bind().unwrap_or_else(|e| {
        crate::log::fatal(&format!("bind failed: {e}"));
    });

    let live = Arc::new(AtomicUsize::new(0));
    let new_session = Arc::new(new_session);

    loop {
        let mut conn = match listener.accept() {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(e) => {
                crate::log::error(&format!("accept failed: {e}"));
                break;
            }
        };

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
}

fn handle_conn<S: Read + Write, H: Handler>(conn: &mut S, session: &mut H) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::StateDir;
    use serde_json::{json, Value};

    struct Echo;

    impl Handler for Echo {
        fn handle(&mut self, msg: Value) -> Option<Value> {
            Some(json!({ "echo": msg }))
        }
    }

    #[cfg(unix)]
    fn round_trip(messages: &[Value]) -> Option<Value> {
        let path = bw_proto::paths::socket_path();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut conn = loop {
            match std::os::unix::net::UnixStream::connect(&path) {
                Ok(c) => break c,
                Err(_) if std::time::Instant::now() < deadline => {
                    thread::sleep(std::time::Duration::from_millis(20))
                }
                Err(e) => panic!("connect {}: {e}", path.display()),
            }
        };
        for m in messages {
            send_message(&mut conn, m);
        }
        read_message(&mut conn)
    }

    #[cfg(windows)]
    fn round_trip(messages: &[Value]) -> Option<Value> {
        let pipe = crate::winpipe::Pipe::connect(&endpoint()).unwrap();
        for m in messages {
            send_message(&mut &pipe, m);
        }
        read_message(&mut &pipe)
    }

    #[test]
    fn a_message_round_trips_and_proxy_notices_get_no_reply() {
        let _state = StateDir::new("ipc");
        thread::spawn(|| serve(|| Echo));

        let reply = round_trip(&[
            json!({"command": "connected"}),
            json!({"appId": "app", "message": "hello"}),
        ])
        .expect("no reply");
        assert_eq!(reply["echo"]["appId"], "app");
        assert_eq!(reply["echo"]["message"], "hello");
    }
}
