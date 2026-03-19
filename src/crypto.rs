use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub struct SymmetricKey {
    raw: Zeroizing<Vec<u8>>,
}

impl SymmetricKey {
    pub fn new(data: Vec<u8>) -> Self {
        assert_eq!(data.len(), 64);
        Self { raw: Zeroizing::new(data) }
    }

    pub fn generate() -> Self {
        let mut buf = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut buf);
        Self::new(buf)
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.raw[..32]
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.raw[32..]
    }
}

pub fn enc_string_encrypt(plaintext: &str, key: &SymmetricKey) -> String {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let encrypted = Aes256CbcEnc::new(key.enc_key().into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

    let mut mac_input = Vec::with_capacity(16 + encrypted.len());
    mac_input.extend_from_slice(&iv);
    mac_input.extend_from_slice(&encrypted);

    let mut hmac = Hmac::<Sha256>::new_from_slice(key.mac_key()).unwrap();
    hmac.update(&mac_input);
    let mac = hmac.finalize().into_bytes();

    format!(
        "2.{}|{}|{}",
        B64.encode(iv),
        B64.encode(&encrypted),
        B64.encode(mac)
    )
}

pub fn enc_string_decrypt(enc_str: &str, key: &SymmetricKey) -> Result<String, &'static str> {
    let raw = enc_string_decrypt_bytes(enc_str, key)?;
    String::from_utf8(raw.to_vec()).map_err(|_| "invalid utf8")
}

pub fn enc_string_decrypt_bytes(enc_str: &str, key: &SymmetricKey) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let (_t, rest) = enc_str.split_once('.').ok_or("bad format")?;
    let parts: Vec<&str> = rest.split('|').collect();
    if parts.len() < 2 {
        return Err("bad format");
    }

    let iv = B64.decode(parts[0]).map_err(|_| "bad iv")?;
    let ct = B64.decode(parts[1]).map_err(|_| "bad ct")?;

    if parts.len() > 2 {
        let mac_got = B64.decode(parts[2]).map_err(|_| "bad mac")?;
        let mut hmac = Hmac::<Sha256>::new_from_slice(key.mac_key()).unwrap();
        let mut mac_input = Vec::with_capacity(iv.len() + ct.len());
        mac_input.extend_from_slice(&iv);
        mac_input.extend_from_slice(&ct);
        hmac.update(&mac_input);
        hmac.verify_slice(&mac_got).map_err(|_| "MAC mismatch")?;
    }

    let decrypted = Aes256CbcDec::new(key.enc_key().into(), iv.as_slice().into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| "decrypt failed")?;

    Ok(Zeroizing::new(decrypted))
}

pub fn enc_string_to_json(enc_str: &str) -> serde_json::Value {
    let (t, rest) = enc_str.split_once('.').unwrap_or(("2", enc_str));
    let parts: Vec<&str> = rest.split('|').collect();
    let mut m = serde_json::Map::new();
    m.insert("encryptionType".into(), serde_json::json!(t.parse::<u32>().unwrap_or(2)));
    m.insert("encryptedString".into(), serde_json::json!(enc_str));
    if let Some(iv) = parts.first() {
        m.insert("iv".into(), serde_json::json!(iv));
    }
    if let Some(data) = parts.get(1) {
        m.insert("data".into(), serde_json::json!(data));
    }
    if let Some(mac) = parts.get(2) {
        m.insert("mac".into(), serde_json::json!(mac));
    }
    serde_json::Value::Object(m)
}

pub fn json_to_enc_string(v: &serde_json::Value) -> String {
    if let Some(s) = v.get("encryptedString").and_then(|s| s.as_str()) {
        return s.to_string();
    }
    let t = v.get("encryptionType").and_then(|t| t.as_u64()).unwrap_or(2);
    let iv = v.get("iv").and_then(|s| s.as_str()).unwrap_or("");
    let data = v.get("data").and_then(|s| s.as_str()).unwrap_or("");
    let mac = v.get("mac").and_then(|s| s.as_str()).unwrap_or("");
    format!("{t}.{iv}|{data}|{mac}")
}
