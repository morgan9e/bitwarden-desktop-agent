
use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};

const TAG: u8 = 0x02;
pub const SECRET_LEN: usize = 32;
const BLOB_LEN: usize = 1 + 32 + SECRET_LEN;

pub struct Token {
    pub server_pub: [u8; 32],
    pub secret: [u8; SECRET_LEN],
}

impl Token {
    pub fn generate(server_pub: [u8; 32]) -> Self {
        Self {
            server_pub,
            secret: crate::rng::bytes(),
        }
    }

    pub fn encode(&self) -> String {
        let mut blob = Vec::with_capacity(BLOB_LEN);
        blob.push(TAG);
        blob.extend_from_slice(&self.server_pub);
        blob.extend_from_slice(&self.secret);
        BASE32_NOPAD.encode(&blob)
    }

    pub fn decode(s: &str) -> Result<Self, String> {
        let cleaned: String = s
            .trim()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let blob = BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| "token is not valid base32".to_string())?;
        if blob.len() != BLOB_LEN || blob[0] != TAG {
            return Err("token is malformed".into());
        }
        let mut server_pub = [0u8; 32];
        let mut secret = [0u8; SECRET_LEN];
        server_pub.copy_from_slice(&blob[1..33]);
        secret.copy_from_slice(&blob[33..]);
        Ok(Self { server_pub, secret })
    }

    pub fn hash(&self) -> [u8; 32] {
        hash_secret(&self.secret)
    }
}

pub fn hash_secret(secret: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(secret);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_tolerates_formatting() {
        let t = Token::generate([9u8; 32]);
        let encoded = t.encode();
        let back = Token::decode(&format!("  {}  ", encoded.to_lowercase())).unwrap();
        assert_eq!(back.server_pub, t.server_pub);
        assert_eq!(back.secret, t.secret);
        assert_eq!(back.hash(), t.hash());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Token::decode("").is_err());
        assert!(Token::decode("not base32 !!").is_err());
        assert!(Token::decode(&BASE32_NOPAD.encode(&[0u8; 65])).is_err());
    }
}
