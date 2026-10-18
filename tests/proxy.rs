//! Drives the real bw-proxy and bw-agent binaries the way a browser does:
//! native-messaging frames on the proxy's stdio, relayed over the socket
//! (or named pipe) to the agent and back.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};

#[cfg(unix)]
const STATE_ENV: &str = "XDG_STATE_HOME";
#[cfg(windows)]
const STATE_ENV: &str = "LOCALAPPDATA";

// A throwaway RSA-2048 public key (SPKI DER), as the extension would send.
const EXTENSION_PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA16aA1G/VdvuqZn/yV9MZSpMojw85Rc6VVKykqb5FavghKUJ37n1OSqLarb3wdilC4VhrSNcnK5lSOyOIej+jLw1h4m1Fn92z06EKrO6L/XkyYiUjp/4X3bOMQqzo+dKCKCAD8c3iwkKGqTXM9YsvcPbZUgC16W2AyriQ4zYy1qjEE6rtA1e//xz5dQsmXt7PjKxol3gHSBvJqXuKurAQ2EHMtr0XXmWIjc+2irB19jyWZfLZfOfcC0utbqkoJcEkgAwgAb0X81CRD2Z1qr7e0eJihnT/MHQuC1Y21ir2siUZoidn1mfz7z2PsGzJG0bPM4By3u8aS6s2EwxlcbHdywIDAQAB";

fn bin(built: &str) -> PathBuf {
    let built = PathBuf::from(built);
    if built.exists() {
        return built;
    }
    // A cross-compiled copy of this test runs beside copies of the binaries.
    let exe = std::env::current_exe().unwrap();
    exe.with_file_name(built.file_name().unwrap())
}

struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

struct Proxy {
    child: Killed,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
}

impl Proxy {
    fn spawn(home: &PathBuf) -> Self {
        let mut child = Command::new(bin(env!("CARGO_BIN_EXE_bw-proxy")))
            .env(STATE_ENV, home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            stdin: child.stdin.take(),
            stdout: child.stdout.take().unwrap(),
            child: Killed(child),
        }
    }

    fn send(&mut self, msg: &Value) {
        let data = serde_json::to_vec(msg).unwrap();
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(&(data.len() as u32).to_ne_bytes()).unwrap();
        stdin.write_all(&data).unwrap();
        stdin.flush().unwrap();
    }

    fn recv(&mut self) -> Option<Value> {
        let mut header = [0u8; 4];
        self.stdout.read_exact(&mut header).ok()?;
        let mut data = vec![0u8; u32::from_ne_bytes(header) as usize];
        self.stdout.read_exact(&mut data).ok()?;
        serde_json::from_slice(&data).ok()
    }
}


/// A state directory with just enough enrollment for `serve()`; no unlock
/// happens in these tests.
fn fake_enrollment(name: &str) -> PathBuf {
    let home = std::env::temp_dir().join(format!("bw-proxy-test-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&home).ok();
    let state = home.join("bw-agent");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(
        state.join("device.toml"),
        "device_id = \"00000000000000000000000000000000\"\n\
         user_id = \"user-1\"\nemail = \"a@example.com\"\nlabel = \"test\"\n",
    )
    .unwrap();
    std::fs::write(state.join("blob"), [0u8; 140]).unwrap();
    home
}

fn wait_listening(home: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !listening(home) {
        assert!(Instant::now() < deadline, "the agent never started listening");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn listening(home: &std::path::Path) -> bool {
    std::os::unix::net::UnixStream::connect(home.join("bw-agent").join("s.bw")).is_ok()
}

#[cfg(windows)]
fn listening(home: &std::path::Path) -> bool {
    win::pipe_exists(&bw_proto::paths::pipe_name_for(&home.join("bw-agent")))
}

fn exchange(proxy: &mut Proxy) {
    proxy.send(&json!({
        "appId": "test-app",
        "message": {
            "command": "setupEncryption",
            "publicKey": EXTENSION_PUBLIC_KEY,
            "userId": "user-1",
            "messageId": -1,
        }
    }));
    let reply = proxy.recv().expect("no reply from the agent");
    assert_eq!(reply["appId"], "test-app");
    assert_eq!(reply["command"], "setupEncryption");
    let secret = B64.decode(reply["sharedSecret"].as_str().unwrap()).unwrap();
    assert_eq!(secret.len(), 256, "RSA-2048 ciphertext");
}

// Closing stdin is how the browser hangs up.
fn hang_up(mut proxy: Proxy) {
    drop(proxy.stdin.take());
    assert_eq!(proxy.recv().unwrap()["command"], "disconnected");
    // The browser must see end-of-file, which it won't if anything the
    // proxy started still holds its stdout.
    assert!(proxy.recv().is_none());
    proxy.child.0.wait().unwrap();
}

#[test]
fn the_proxy_relays_a_key_exchange_to_the_agent() {
    let home = fake_enrollment("relay");
    let _agent = Killed(
        Command::new(bin(env!("CARGO_BIN_EXE_bw-agent")))
            .args(["--askpass", "cli"])
            .env(STATE_ENV, &home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_listening(&home);

    let mut proxy = Proxy::spawn(&home);
    assert_eq!(proxy.recv().unwrap()["command"], "connected");
    exchange(&mut proxy);
    hang_up(proxy);

    std::fs::remove_dir_all(&home).ok();
}

#[cfg(windows)]
#[test]
fn the_proxy_starts_the_agent_and_it_outlives_the_browser_job() {
    let home = fake_enrollment("autostart");
    assert!(!listening(&home));

    let job = win::Job::like_a_browser();
    let mut proxy = Proxy::spawn(&home);
    job.assign(&proxy.child.0);
    assert_eq!(
        proxy.recv().expect("the proxy gave up instead of starting the agent")["command"],
        "connected"
    );
    exchange(&mut proxy);

    let launcher = win::child_named(proxy.child.0.id(), "bw-agentw.exe")
        .expect("the proxy did not start bw-agentw");
    let _cleanup = win::KillTree(launcher);
    hang_up(proxy);

    // What the browser does once its host has exited.
    drop(job);
    std::thread::sleep(Duration::from_millis(300));
    assert!(win::alive(launcher), "bw-agentw was killed along with the browser's job");

    // The next connection finds it running and starts nothing new.
    let mut again = Proxy::spawn(&home);
    let again_pid = again.child.0.id();
    assert_eq!(again.recv().unwrap()["command"], "connected");
    exchange(&mut again);
    hang_up(again);
    assert!(win::child_named(again_pid, "bw-agentw.exe").is_none());

    std::fs::remove_dir_all(&home).ok();
}

#[cfg(windows)]
#[test]
fn the_proxy_does_not_start_an_agent_for_an_unenrolled_device() {
    let home = fake_enrollment("unenrolled");
    std::fs::remove_file(home.join("bw-agent").join("blob")).unwrap();

    let mut proxy = Proxy::spawn(&home);
    let pid = proxy.child.0.id();
    assert!(proxy.recv().is_none(), "the proxy should exit without connecting");
    assert!(!proxy.child.0.wait().unwrap().success());
    assert!(win::child_named(pid, "bw-agentw.exe").is_none());

    std::fs::remove_dir_all(&home).ok();
}

#[cfg(windows)]
#[test]
fn a_second_launcher_backs_off() {
    let home = fake_enrollment("single");
    let launch = || {
        let mut cmd = Command::new(bin(env!("CARGO_BIN_EXE_bw-agentw")));
        cmd.env(STATE_ENV, &home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    };
    let first = launch().spawn().unwrap();
    let _cleanup = win::KillTree(first.id());
    wait_listening(&home);

    let started = Instant::now();
    assert!(launch().status().unwrap().success());
    assert!(started.elapsed() < Duration::from_secs(2), "the second launcher did not back off");
    assert!(win::alive(first.id()));

    std::fs::remove_dir_all(&home).ok();
}

#[cfg(windows)]
mod win {
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_FILE_NOT_FOUND, HANDLE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_TERMINATE,
    };

    const STILL_ACTIVE: u32 = 259;

    pub fn pipe_exists(name: &str) -> bool {
        let name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe { WaitNamedPipeW(name.as_ptr(), 1) != 0 || GetLastError() != ERROR_FILE_NOT_FOUND }
    }

    /// A job set up the way Firefox sets one up for a native host: everything
    /// in it dies when it is closed, but children may break away.
    pub struct Job(HANDLE);

    impl Job {
        pub fn like_a_browser() -> Self {
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                assert!(!job.is_null());
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags =
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
                assert_ne!(
                    SetInformationJobObject(
                        job,
                        JobObjectExtendedLimitInformation,
                        &info as *const _ as *const _,
                        std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                    ),
                    0
                );
                Self(job)
            }
        }

        pub fn assign(&self, child: &Child) {
            let ok = unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as HANDLE) };
            assert_ne!(ok, 0, "AssignProcessToJobObject failed");
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    fn processes() -> Vec<(u32, u32, String)> {
        let mut out = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut ok = Process32FirstW(snap, &mut entry);
            while ok != 0 {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                out.push((entry.th32ProcessID, entry.th32ParentProcessID, name));
                ok = Process32NextW(snap, &mut entry);
            }
            CloseHandle(snap);
        }
        out
    }

    pub fn child_named(parent: u32, name: &str) -> Option<u32> {
        processes()
            .into_iter()
            .find(|(_, ppid, n)| *ppid == parent && n.eq_ignore_ascii_case(name))
            .map(|(pid, _, _)| pid)
    }

    pub fn alive(pid: u32) -> bool {
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let mut code = 0u32;
            let ok = GetExitCodeProcess(h, &mut code);
            CloseHandle(h);
            ok != 0 && code == STILL_ACTIVE
        }
    }

    fn kill(pid: u32) {
        unsafe {
            let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
            if !h.is_null() {
                TerminateProcess(h, 1);
                CloseHandle(h);
            }
        }
    }

    /// Kills a launcher this test started and the agent under it — the
    /// launcher first, so it can't restart the agent. Only processes
    /// descended from the test are touched.
    pub struct KillTree(pub u32);

    impl Drop for KillTree {
        fn drop(&mut self) {
            let agent = child_named(self.0, "bw-agent.exe");
            kill(self.0);
            if let Some(pid) = agent {
                kill(pid);
            }
        }
    }
}
