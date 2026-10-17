use std::io::{self, Read, Write};
use std::thread;

#[cfg(windows)]
#[allow(dead_code)]
#[path = "winpipe.rs"]
mod winpipe;

const MAX_MSG: usize = 1024 * 1024;

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

fn read_ipc<R: Read>(sock: &mut R) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    sock.read_exact(&mut header).ok()?;
    let length = u32::from_ne_bytes(header) as usize;
    if length == 0 || length > MAX_MSG {
        return None;
    }
    let mut data = vec![0u8; length];
    sock.read_exact(&mut data).ok()?;
    Some(data)
}

fn send_ipc<W: Write>(sock: &mut W, data: &[u8]) {
    let len_bytes = (data.len() as u32).to_ne_bytes();
    let _ = sock.write_all(&len_bytes);
    let _ = sock.write_all(data);
    let _ = sock.flush();
}

#[cfg(unix)]
fn endpoint() -> String {
    bw_proto::paths::socket_path().display().to_string()
}

#[cfg(unix)]
fn connect() -> io::Result<(impl Read + Send + 'static, impl Write)> {
    let sock = std::os::unix::net::UnixStream::connect(bw_proto::paths::socket_path())?;
    Ok((sock.try_clone()?, sock))
}

#[cfg(windows)]
fn endpoint() -> String {
    bw_proto::paths::pipe_name()
}

#[cfg(windows)]
fn connect() -> io::Result<(impl Read + Send + 'static, impl Write)> {
    use std::sync::Arc;

    struct Shared(Arc<winpipe::Pipe>);

    impl Read for Shared {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            (&*self.0).read(buf)
        }
    }

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            (&*self.0).write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let pipe = Arc::new(winpipe::Pipe::connect(&bw_proto::paths::pipe_name())?);
    Ok((Shared(pipe.clone()), Shared(pipe)))
}

const CONNECTED: &[u8] = b"{\"command\":\"connected\"}";
const DISCONNECTED: &[u8] = b"{\"command\":\"disconnected\"}";

fn main() {
    let (mut reader, mut writer) = connect().unwrap_or_else(|e| {
        eprintln!("bw-proxy: connect {}: {e}", endpoint());
        std::process::exit(1);
    });

    write_stdout(CONNECTED);

    thread::spawn(move || {
        while let Some(msg) = read_ipc(&mut reader) {
            write_stdout(&msg);
        }
        write_stdout(DISCONNECTED);
        std::process::exit(0);
    });

    while let Some(msg) = read_stdin() {
        send_ipc(&mut writer, &msg);
    }

    write_stdout(DISCONNECTED);
}
