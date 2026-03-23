use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use zeroize::Zeroize;

use super::KeyStore;

fn store_dir() -> PathBuf {
    super::pin::cache_dir()
        .join("com.bitwarden.desktop")
        .join("keys")
}

pub struct Tpm2KeyStore {
    dir: PathBuf,
}

impl Tpm2KeyStore {
    pub fn new(dir: Option<PathBuf>) -> Self {
        let dir = dir.unwrap_or_else(store_dir);
        fs::create_dir_all(&dir).ok();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).ok();
        }
        Self { dir }
    }

    fn pub_path(&self, uid: &str) -> PathBuf {
        self.dir.join(format!("{uid}.pub"))
    }

    fn priv_path(&self, uid: &str) -> PathBuf {
        self.dir.join(format!("{uid}.priv"))
    }
}

impl KeyStore for Tpm2KeyStore {
    fn name(&self) -> &str {
        "tpm2"
    }

    fn is_available(&self) -> bool {
        Command::new("tpm2_getcap")
            .arg("properties-fixed")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn has_key(&self, uid: &str) -> bool {
        self.pub_path(uid).exists() && self.priv_path(uid).exists()
    }

    fn store(&self, uid: &str, data: &[u8], auth: &str) -> Result<(), String> {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let ctx = tmp.path().join("primary.ctx");
        let dat = tmp.path().join("data.bin");

        fs::write(&dat, data).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dat, fs::Permissions::from_mode(0o600)).ok();
        }

        run(&[
            "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "aes256cfb",
            "-c", &ctx.to_string_lossy(),
        ], None)?;

        let pub_path = self.pub_path(uid);
        let priv_path = self.priv_path(uid);

        let result = run(&[
            "tpm2_create", "-C", &ctx.to_string_lossy(),
            "-i", &dat.to_string_lossy(),
            "-u", &pub_path.to_string_lossy(),
            "-r", &priv_path.to_string_lossy(),
            "-p", "file:-",
        ], Some(auth.as_bytes()));

        // overwrite plaintext before temp dir cleanup
        let mut zeros = vec![0u8; data.len()];
        fs::File::create(&dat).ok().map(|mut f| f.write_all(&zeros));
        zeros.zeroize();

        result?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o600)).ok();
            fs::set_permissions(&priv_path, fs::Permissions::from_mode(0o600)).ok();
        }

        Ok(())
    }

    fn load(&self, uid: &str, auth: &str) -> Result<Vec<u8>, String> {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let ctx = tmp.path().join("primary.ctx");
        let loaded = tmp.path().join("loaded.ctx");

        run(&[
            "tpm2_createprimary", "-C", "o", "-g", "sha256", "-G", "aes256cfb",
            "-c", &ctx.to_string_lossy(),
        ], None)?;

        run(&[
            "tpm2_load", "-C", &ctx.to_string_lossy(),
            "-u", &self.pub_path(uid).to_string_lossy(),
            "-r", &self.priv_path(uid).to_string_lossy(),
            "-c", &loaded.to_string_lossy(),
        ], None)?;

        let mut child = Command::new("tpm2_unseal")
            .args(["-c", &loaded.to_string_lossy(), "-p", "file:-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| e.to_string())?;

        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(auth.as_bytes());
        }

        let mut out = child.wait_with_output().map_err(|e| e.to_string())?;

        if !out.status.success() {
            out.stdout.zeroize();
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }

        out.stderr.zeroize();
        Ok(out.stdout)
    }

    fn remove(&self, uid: &str) {
        for p in [self.pub_path(uid), self.priv_path(uid)] {
            if p.exists() {
                fs::remove_file(p).ok();
            }
        }
    }

    fn find_key(&self) -> Option<String> {
        let entries = fs::read_dir(&self.dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pub") {
                let uid = path.file_stem()?.to_str()?;
                if self.priv_path(uid).exists() {
                    return Some(uid.to_string());
                }
            }
        }
        None
    }
}

fn run(args: &[&str], stdin_data: Option<&[u8]>) -> Result<(), String> {
    let mut cmd = Command::new(args[0]);
    cmd.args(&args[1..]).stderr(Stdio::piped());

    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }

    let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", args[0]))?;

    if let Some(data) = stdin_data {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(data);
        }
    }

    let out = child.wait_with_output().map_err(|e| e.to_string())?;

    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}
