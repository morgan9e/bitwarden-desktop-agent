//! `device.toml` — non-secret local configuration.
//!
//! Everything here is public or merely identifying. The two secrets in the state
//! directory are `blob` and `identity.key`, both `0600`, neither of which is
//! described by this file.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// 16 random bytes, hex. Assigned at enrollment; never reused, even after
    /// revocation.
    pub device_id: String,
    /// Bitwarden account GUID (the `sub` claim). The extension names a `userId`
    /// on every unlock; if it does not match this, the request is for a
    /// different account and must be refused rather than answered.
    pub user_id: String,
    pub email: String,
    pub label: String,
    /// OPRF server, `host:port`. Absent until enrolled against one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Server Noise static public key, base64. Pinned: a mismatch is a hard
    /// failure, never a prompt to accept.
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

    /// Case-insensitive: the extension and the JWT do not agree on GUID casing.
    pub fn owns_user(&self, user_id: &str) -> bool {
        self.user_id.eq_ignore_ascii_case(user_id)
    }
}

pub fn new_device_id() -> String {
    hex::encode(bw_proto::rng::bytes::<16>())
}

/// The Noise static private key identifying this device to the server. Created
/// on first enrollment and preserved across re-enrollments so the server-side
/// row stays valid.
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

/// Decodes the pinned server static key from `device.toml`.
pub fn server_public(device: &Device) -> Result<[u8; 32], String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let encoded = device
        .server_pub
        .as_deref()
        .ok_or("device.toml has no server_pub — re-enroll against the server")?;
    let bytes = B64.decode(encoded).map_err(|_| "server_pub is not base64")?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| "server_pub is not 32 bytes".into())
}
