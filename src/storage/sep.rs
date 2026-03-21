use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use super::KeyStore;

fn helper_path() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_default();
    let dir = exe.parent().unwrap_or(std::path::Path::new("."));
    dir.join("sep-helper")
}

pub struct SEPKeyStore;

impl SEPKeyStore {
    pub fn new() -> Self {
        Self
    }
}

impl KeyStore for SEPKeyStore {
    fn name(&self) -> &str {
        "sep"
    }

    fn is_available(&self) -> bool {
        helper_path().exists()
    }

    fn has_key(&self, uid: &str) -> bool {
        Command::new(helper_path())
            .args(["has", uid])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn store(&self, uid: &str, data: &[u8], _auth: &str) -> Result<(), String> {
        let b64 = B64.encode(data);
        let out = Command::new(helper_path())
            .args(["store", uid])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(b64.as_bytes())?;
                child.wait_with_output()
            })
            .map_err(|e| e.to_string())?;

        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(())
    }

    fn load(&self, uid: &str, _auth: &str) -> Result<Vec<u8>, String> {
        let out = Command::new(helper_path())
            .args(["load", uid])
            .output()
            .map_err(|e| e.to_string())?;

        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }

        let b64 = String::from_utf8_lossy(&out.stdout).trim().to_string();
        B64.decode(&b64).map_err(|e| e.to_string())
    }

    fn remove(&self, uid: &str) {
        Command::new(helper_path())
            .args(["remove", uid])
            .output()
            .ok();
    }

    fn find_key(&self) -> Option<String> {
        None
    }
}
