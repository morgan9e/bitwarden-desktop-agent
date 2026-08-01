
use std::path::{Path, PathBuf};

pub const DB_FILE: &str = "devices.db";
pub const KEY_FILE: &str = "server.key";

pub fn default_dir() -> PathBuf {
    match std::env::var("STATE_DIRECTORY") {
        Ok(v) if !v.is_empty() => PathBuf::from(v.split(':').next().unwrap_or(&v)),
        _ => PathBuf::from("/var/lib/bw-key"),
    }
}

pub fn ensure_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())
}

pub fn load_or_create_key(dir: &Path) -> Result<[u8; 32], String> {
    let path = dir.join(KEY_FILE);
    if path.exists() {
        let raw = std::fs::read(&path).map_err(|e| e.to_string())?;
        if raw.len() != 32 {
            return Err(format!(
                "{}: expected 32 bytes, found {}",
                path.display(),
                raw.len()
            ));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        return Ok(k);
    }

    let key = bw_proto::noise::generate_private_key();
    write_secret(&path, &key)?;
    Ok(key)
}

pub fn write_secret(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
