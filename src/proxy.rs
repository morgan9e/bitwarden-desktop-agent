use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::thread;

const MAX_MSG: usize = 1024 * 1024;

fn socket_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".cache")
        .join("com.bitwarden.desktop")
        .join("s.bw")
        .to_string_lossy()
        .into_owned()
}

fn read_stdin() -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    io::stdin().read_exact(&mut header).ok()?;
    let length = u32::from_ne_bytes(header) as usize;
    if length == 0 || length > MAX_MSG {
        return None;
    }
    let mut data = vec![0u8; length];
    io::stdin().read_exact(&mut data).ok()?;
    Some(data)
}

fn write_stdout(data: &[u8]) {
    let len_bytes = (data.len() as u32).to_ne_bytes();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let _ = out.write_all(&len_bytes);
    let _ = out.write_all(data);
    let _ = out.flush();
}

fn recv_exact(sock: &mut UnixStream, n: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut pos = 0;
    while pos < n {
        match sock.read(&mut buf[pos..]) {
            Ok(0) => return None,
            Ok(k) => pos += k,
            Err(_) => return None,
        }
    }
    Some(buf)
}

fn read_ipc(sock: &mut UnixStream) -> Option<Vec<u8>> {
    let header = recv_exact(sock, 4)?;
    let length = u32::from_ne_bytes(header[..4].try_into().ok()?) as usize;
    if length == 0 || length > MAX_MSG {
        return None;
    }
    recv_exact(sock, length)
}

fn send_ipc(sock: &mut UnixStream, data: &[u8]) {
    let len_bytes = (data.len() as u32).to_ne_bytes();
    let _ = sock.write_all(&len_bytes);
    let _ = sock.write_all(data);
}

fn main() {
    let mut sock = UnixStream::connect(socket_path()).unwrap_or_else(|_| std::process::exit(1));

    send_ipc(&mut sock, b"{\"command\":\"connected\"}");

    let mut sock2 = sock.try_clone().unwrap();
    thread::spawn(move || {
        loop {
            match read_ipc(&mut sock2) {
                Some(msg) => write_stdout(&msg),
                None => break,
            }
        }
    });

    loop {
        match read_stdin() {
            Some(msg) => send_ipc(&mut sock, &msg),
            None => break,
        }
    }

    let _ = send_ipc(&mut sock, b"{\"command\":\"disconnected\"}");
}
