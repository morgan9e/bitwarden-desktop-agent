use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::{pkcs1::DecodeRsaPublicKey, Oaep};
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::askpass::Prompter;
use crate::crypto::{
    enc_string_decrypt_bytes, enc_string_encrypt, enc_string_to_json, json_to_enc_string,
    SymmetricKey,
};
use crate::storage::KeyStore;

const KEY_PLACEHOLDER: &str = "__KEY_PLACEHOLDER_00000000_00000000__";

pub struct BiometricBridge {
    store: Box<dyn KeyStore>,
    uid: String,
    prompt: Prompter,
    sessions: HashMap<String, SymmetricKey>,
    pending_key: Option<String>,
}

impl BiometricBridge {
    pub fn new(store: Box<dyn KeyStore>, uid: String, prompt: Prompter) -> Self {
        Self {
            store,
            uid,
            prompt,
            sessions: HashMap::new(),
            pending_key: None,
        }
    }

    pub fn handle(&mut self, msg: Value) -> Option<Value> {
        let app_id = msg.get("appId")?.as_str()?.to_string();
        let message = msg.get("message")?;

        if let Some(obj) = message.as_object() {
            if obj.get("command").and_then(|c| c.as_str()) == Some("setupEncryption") {
                return Some(self.handshake(&app_id, message));
            }
            if obj.contains_key("encryptedString") || obj.contains_key("encryptionType") {
                return self.encrypted(&app_id, message);
            }
        }

        if let Some(s) = message.as_str() {
            if s.starts_with("2.") {
                return self.encrypted(&app_id, &json!({"encryptedString": s}));
            }
        }

        None
    }

    fn handshake(&mut self, app_id: &str, msg: &Value) -> Value {
        let pub_b64 = msg
            .get("publicKey")
            .and_then(|p| p.as_str())
            .unwrap_or("");
        let pub_bytes = B64.decode(pub_b64).unwrap_or_default();
        let pub_key = rsa::RsaPublicKey::from_pkcs1_der(&pub_bytes)
            .or_else(|_| {
                use rsa::pkcs8::DecodePublicKey;
                rsa::RsaPublicKey::from_public_key_der(&pub_bytes)
            })
            .unwrap_or_else(|e| crate::log::fatal(&format!("bad public key: {e}")));

        let shared = SymmetricKey::generate();
        let encrypted = pub_key
            .encrypt(
                &mut rand::thread_rng(),
                Oaep::new::<sha1::Sha1>(),
                shared.raw(),
            )
            .unwrap_or_else(|e| crate::log::fatal(&format!("RSA encrypt failed: {e}")));

        self.sessions.insert(app_id.to_string(), shared);

        crate::log::info(&format!("handshake complete, app={}", &app_id[..12.min(app_id.len())]));
        json!({
            "appId": app_id,
            "command": "setupEncryption",
            "messageId": -1,
            "sharedSecret": B64.encode(encrypted),
        })
    }

    fn encrypted(&mut self, app_id: &str, enc_msg: &Value) -> Option<Value> {
        if !self.sessions.contains_key(app_id) {
            crate::log::warn(&format!(
                "no session for app={}",
                &app_id[..12.min(app_id.len())]
            ));
            return Some(json!({"appId": app_id, "command": "invalidateEncryption"}));
        }

        let key = self.sessions.get(app_id).unwrap();
        let enc_str = json_to_enc_string(enc_msg);
        let plaintext = match enc_string_decrypt_bytes(&enc_str, key) {
            Ok(p) => p,
            Err(_) => {
                crate::log::error("message decryption failed");
                return Some(json!({"appId": app_id, "command": "invalidateEncryption"}));
            }
        };

        let data: Value = serde_json::from_slice(&plaintext).ok()?;
        let cmd = data.get("command")?.as_str()?.to_string();
        let mid = data.get("messageId").and_then(|m| m.as_i64()).unwrap_or(0);

        crate::log::info(&format!("<- {cmd} (msg={mid})"));
        let resp = self.dispatch(&cmd, mid)?;

        let key = self.sessions.get(app_id).unwrap();
        let mut resp_json = serde_json::to_string(&resp).unwrap();

        if let Some(mut real_key) = self.pending_key.take() {
            resp_json = resp_json.replace(KEY_PLACEHOLDER, &real_key);
            real_key.zeroize();
        }

        let encrypted = enc_string_encrypt(&resp_json, key);
        resp_json.zeroize();

        Some(json!({
            "appId": app_id,
            "messageId": mid,
            "message": enc_string_to_json(&encrypted),
        }))
    }

    fn reply(&self, cmd: &str, mid: i64, extra: Value) -> Value {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let mut obj = json!({
            "command": cmd,
            "messageId": mid,
            "timestamp": ts,
        });
        if let (Some(base), Some(ext)) = (obj.as_object_mut(), extra.as_object()) {
            for (k, v) in ext {
                base.insert(k.clone(), v.clone());
            }
        }
        obj
    }

    fn dispatch(&mut self, cmd: &str, mid: i64) -> Option<Value> {
        match cmd {
            "unlockWithBiometricsForUser" => Some(self.handle_unlock(cmd, mid)),
            "getBiometricsStatus" | "getBiometricsStatusForUser" => {
                crate::log::info("-> biometrics available");
                Some(self.reply(cmd, mid, json!({"response": 0})))
            }
            "authenticateWithBiometrics" => {
                crate::log::info("-> authenticated");
                Some(self.reply(cmd, mid, json!({"response": true})))
            }
            _ => {
                crate::log::warn(&format!("unhandled command: {cmd}"));
                None
            }
        }
    }

    fn handle_unlock(&mut self, cmd: &str, mid: i64) -> Value {
        match self.unseal_key() {
            Some(mut key_b64) => {
                crate::log::info("-> unlock granted");
                let resp = self.reply(cmd, mid, json!({"response": true, "userKeyB64": KEY_PLACEHOLDER}));
                self.pending_key = Some(std::mem::take(&mut key_b64));
                resp
            }
            None => {
                crate::log::warn("unlock denied or failed");
                self.reply(cmd, mid, json!({"response": false}))
            }
        }
    }

    fn unseal_key(&self) -> Option<String> {
        let mut pw = (self.prompt)(&format!("Enter {} password:", self.store.name().to_uppercase()))?;
        let result = match self.store.load(&self.uid, &pw) {
            Ok(mut raw) => {
                let len = raw.len();
                let b64 = B64.encode(&raw);
                raw.zeroize();
                crate::log::info(&format!("unsealed {len}B from {}", self.store.name()));
                Some(b64)
            }
            Err(e) => {
                crate::log::error(&format!("unseal failed: {e}"));
                None
            }
        };
        pw.zeroize();
        result
    }
}
