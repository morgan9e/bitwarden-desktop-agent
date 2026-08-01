
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub user_id: String,
    pub email: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_pub: Option<String>,
}

impl Device {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        toml::from_str(&text).map_err(|e| e.to_string())
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = toml::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::blob::write_atomic(path, text.as_bytes())
    }

    pub fn owns_user(&self, user_id: &str) -> bool {
        self.user_id.eq_ignore_ascii_case(user_id)
    }
}

pub fn new_device_id() -> String {
    hex::encode(bw_proto::rng::bytes::<16>())
}

pub fn load_or_create_identity() -> Result<[u8; 32], String> {
    let path = bw_proto::paths::identity_path();
    if path.exists() {
        let raw = std::fs::read(&path).map_err(|e| e.to_string())?;
        return <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| format!("{}: expected 32 bytes", path.display()));
    }

    let key = bw_proto::noise::generate_private_key();
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(&key).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn server_public(device: &Device) -> Result<[u8; 32], String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let encoded = device
        .server_pub
        .as_deref()
        .ok_or("device.toml has no server_pub — re-enroll against the server")?;
    let bytes = B64.decode(encoded).map_err(|_| "server_pub is not base64")?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "server_pub is not 32 bytes".into())
}
