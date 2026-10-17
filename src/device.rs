
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

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

pub fn load_identity() -> Result<Zeroizing<[u8; 32]>, String> {
    let path = bw_proto::paths::identity_path();
    let raw = Zeroizing::new(
        std::fs::read(&path)
            .map_err(|e| format!("{}: {e} — re-enroll with --server and --token", path.display()))?,
    );
    <[u8; 32]>::try_from(raw.as_slice())
        .map(Zeroizing::new)
        .map_err(|_| format!("{}: expected 32 bytes", path.display()))
}

pub fn save_identity(key: &[u8; 32]) -> Result<(), String> {
    crate::blob::write_atomic(&bw_proto::paths::identity_path(), key)
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
