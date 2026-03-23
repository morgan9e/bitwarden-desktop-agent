use std::fs;
use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use scrypt::{scrypt, Params};
use zeroize::Zeroizing;

use super::KeyStore;

const VERSION: u8 = 1;
const SCRYPT_LOG_N: u8 = 17;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

pub(super) fn cache_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".cache")
}

fn store_dir() -> PathBuf {
    cache_dir()
        .join("com.bitwarden.desktop")
        .join("keys")
}

pub struct PinKeyStore {
    dir: PathBuf,
}

impl PinKeyStore {
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

    fn path(&self, uid: &str) -> PathBuf {
        self.dir.join(format!("{uid}.enc"))
    }
}

impl KeyStore for PinKeyStore {
    fn name(&self) -> &str {
        "pin"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn has_key(&self, uid: &str) -> bool {
        self.path(uid).exists()
    }

    fn store(&self, uid: &str, data: &[u8], auth: &str) -> Result<(), String> {
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let key = derive(auth, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: data, aad: &salt })
            .map_err(|e| e.to_string())?;

        let mut blob = Vec::with_capacity(1 + 32 + 12 + ct.len());
        blob.push(VERSION);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        let path = self.path(uid);
        fs::write(&path, &blob).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();
        }
        Ok(())
    }

    fn load(&self, uid: &str, auth: &str) -> Result<Vec<u8>, String> {
        let blob = fs::read(self.path(uid)).map_err(|e| e.to_string())?;
        if blob.len() <= 1 + 32 + 12 + 16 {
            return Err("file too short".into());
        }

        let salt = &blob[1..33];
        let nonce_bytes = &blob[33..45];
        let ct = &blob[45..];

        let key = derive(auth, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, aes_gcm::aead::Payload { msg: ct, aad: salt })
            .map_err(|_| "wrong password or corrupted data".into())
    }

    fn remove(&self, uid: &str) {
        let p = self.path(uid);
        if p.exists() {
            fs::remove_file(p).ok();
        }
    }

    fn find_key(&self) -> Option<String> {
        let entries = fs::read_dir(&self.dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("enc") {
                return path.file_stem().and_then(|s| s.to_str()).map(|s| s.to_string());
            }
        }
        None
    }
}

fn derive(password: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32).map_err(|e| e.to_string())?;
    let mut key = Zeroizing::new(vec![0u8; 32]);
    scrypt(password.as_bytes(), salt, &params, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}
