//! Drives the real bw-proxy and bw-agent binaries the way a browser does:
//! native-messaging frames on the proxy's stdio, relayed over the socket
//! (or named pipe) to the agent and back.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

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

#[test]
fn the_proxy_relays_a_key_exchange_to_the_agent() {
    let home = std::env::temp_dir().join(format!("bw-proxy-test-{}", std::process::id()));
    std::fs::remove_dir_all(&home).ok();
    let state = home.join("bw-agent");
    std::fs::create_dir_all(&state).unwrap();

    // serve() only needs an enrollment to exist; no unlock happens here.
    std::fs::write(
        state.join("device.toml"),
        "device_id = \"00000000000000000000000000000000\"\n\
         user_id = \"user-1\"\nemail = \"a@example.com\"\nlabel = \"test\"\n",
    )
    .unwrap();
    std::fs::write(state.join("blob"), [0u8; 140]).unwrap();

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

    // The proxy exits straight away if the agent isn't listening yet.
    let mut proxy = (0..50)
        .find_map(|_| {
            let mut p = Proxy::spawn(&home);
            match p.recv() {
                Some(m) if m["command"] == "connected" => Some(p),
                _ => {
                    std::thread::sleep(Duration::from_millis(100));
                    None
                }
            }
        })
        .expect("the proxy never connected to the agent");

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

    // Closing stdin is how the browser hangs up.
    drop(proxy.stdin.take());
    assert_eq!(proxy.recv().unwrap()["command"], "disconnected");
    proxy.child.0.wait().unwrap();

    std::fs::remove_dir_all(&home).ok();
}
