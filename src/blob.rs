
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const USER_KEY_LEN: usize = 64;
const PADDING_LEN: usize = 16;
const PLAINTEXT_LEN: usize = USER_KEY_LEN + PADDING_LEN;
const TAG_LEN: usize = 16;
const CT_LEN: usize = PLAINTEXT_LEN + TAG_LEN;
pub const BLOB_LEN: usize = SALT_LEN + NONCE_LEN + CT_LEN;

pub struct Blob {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ct: [u8; CT_LEN],
}

impl Blob {
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let raw = fs::read(path).map_err(|e| e.to_string())?;
        Self::parse(&raw)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.len() != BLOB_LEN {
            return Err(format!(
                "unrecognised blob: {} bytes, expected {BLOB_LEN}",
                raw.len()
            ));
        }
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        let mut ct = [0u8; CT_LEN];
        salt.copy_from_slice(&raw[..SALT_LEN]);
        nonce.copy_from_slice(&raw[SALT_LEN..SALT_LEN + NONCE_LEN]);
        ct.copy_from_slice(&raw[SALT_LEN + NONCE_LEN..]);
        Ok(Self { salt, nonce, ct })
    }

    pub fn decrypt(&self, k: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, ()> {
        let cipher = Aes256Gcm::new_from_slice(k).map_err(|_| ())?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ct,
                    aad: &self.salt,
                },
            )
            .map_err(|_| ())?;
        let pt = Zeroizing::new(pt);
        if pt.len() != PLAINTEXT_LEN {
            return Err(());
        }
        Ok(Zeroizing::new(pt[..USER_KEY_LEN].to_vec()))
    }
}

pub fn exists(path: &Path) -> bool {
    path.is_file()
}

pub fn write(path: &Path, salt: &[u8; SALT_LEN], user_key: &[u8], k: &[u8; 32]) -> Result<(), String> {
    if user_key.len() != USER_KEY_LEN {
        return Err(format!(
            "user key is {} bytes, expected {USER_KEY_LEN}",
            user_key.len()
        ));
    }

    let mut pt = Zeroizing::new(vec![0u8; PLAINTEXT_LEN]);
    pt[..USER_KEY_LEN].copy_from_slice(user_key);

    let nonce: [u8; NONCE_LEN] = bw_proto::rng::bytes();

    let cipher = Aes256Gcm::new_from_slice(k).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: salt.as_slice(),
            },
        )
        .map_err(|e| e.to_string())?;

    let mut out = Vec::with_capacity(BLOB_LEN);
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    debug_assert_eq!(out.len(), BLOB_LEN);

    write_atomic(path, &out)
}

pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| "path has no parent directory".to_string())?;
    let tmp: PathBuf = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("blob")
    ));

    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(data).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }

    fs::rename(&tmp, path).map_err(|e| {
        fs::remove_file(&tmp).ok();
        e.to_string()
    })?;

    if let Ok(d) = fs::File::open(dir) {
        d.sync_all().ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bw-blob-test-{name}"));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn round_trip_recovers_the_user_key() {
        let dir = tmpdir("roundtrip");
        let path = dir.join("blob");
        let salt = [7u8; SALT_LEN];
        let k = [3u8; 32];
        let user_key: Vec<u8> = (0..USER_KEY_LEN).map(|i| i as u8).collect();

        write(&path, &salt, &user_key, &k).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len() as usize, BLOB_LEN);

        let blob = Blob::read(&path).unwrap();
        assert_eq!(blob.salt(), &salt);
        assert_eq!(&blob.decrypt(&k).unwrap()[..], &user_key[..]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_key_fails_without_detail() {
        let dir = tmpdir("wrongkey");
        let path = dir.join("blob");
        let salt = [7u8; SALT_LEN];
        write(&path, &salt, &[0u8; USER_KEY_LEN], &[3u8; 32]).unwrap();
        assert!(Blob::read(&path).unwrap().decrypt(&[4u8; 32]).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn length_is_checked_before_parsing() {
        assert!(Blob::parse(&[0u8; BLOB_LEN - 1]).is_err());
        assert!(Blob::parse(&[0u8; BLOB_LEN + 1]).is_err());
        assert!(Blob::parse(&[0u8; BLOB_LEN]).is_ok());
    }

    #[test]
    fn tampering_with_the_salt_breaks_the_aead() {
        let salt = [7u8; SALT_LEN];
        let k = [3u8; 32];
        let dir = tmpdir("aad");
        let path = dir.join("blob");
        write(&path, &salt, &[1u8; USER_KEY_LEN], &k).unwrap();

        let mut raw = fs::read(&path).unwrap();
        raw[0] ^= 0xff;
        assert!(Blob::parse(&raw).unwrap().decrypt(&k).is_err());
        fs::remove_dir_all(&dir).ok();
    }
}
