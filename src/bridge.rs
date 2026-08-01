use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rsa::{pkcs1::DecodeRsaPublicKey, Oaep};
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::crypto::{
    enc_string_decrypt_bytes, enc_string_encrypt, enc_string_to_json, json_to_enc_string,
    SymmetricKey,
};
use crate::ipc::Handler;
use crate::unlock::{UnlockError, Unlocker};

const KEY_PLACEHOLDER: &str = "__KEY_PLACEHOLDER_00000000_00000000__";

pub struct Bridge {
    unlocker: Unlocker,
    unlocking: Mutex<()>,
}

impl Bridge {
    pub fn new(unlocker: Unlocker) -> Self {
        Self {
            unlocker,
            unlocking: Mutex::new(()),
        }
    }

    fn owns_user(&self, user_id: Option<&str>) -> bool {
        match user_id {
            Some(id) => self.unlocker.device().owns_user(id),
            None => true,
        }
    }

    fn unseal_key(&self) -> Option<String> {
        let _guard = self.unlocking.lock().unwrap_or_else(|e| e.into_inner());
        match self.unlocker.unlock() {
            Ok(user_key) => {
                crate::log::info(&format!("unsealed {}B", user_key.len()));
                Some(B64.encode(&user_key))
            }
            Err(e) => {
                match e {
                    UnlockError::NotEnrolled | UnlockError::Server(_) => {
                        crate::log::error(&format!("{e}"))
                    }
                    UnlockError::Cancelled => crate::log::info("prompt cancelled"),
                    UnlockError::Failed => crate::log::error("unlock failed"),
                }
                None
            }
        }
    }
}

pub struct Session {
    bridge: Arc<Bridge>,
    shared: Option<SymmetricKey>,
    pending_key: Option<String>,
}

impl Session {
    pub fn new(bridge: Arc<Bridge>) -> Self {
        Self {
            bridge,
            shared: None,
            pending_key: None,
        }
    }

    fn handshake(&mut self, app_id: &str, msg: &Value) -> Value {
        let invalidate = || json!({"appId": app_id, "command": "invalidateEncryption"});

        let pub_b64 = msg.get("publicKey").and_then(|p| p.as_str()).unwrap_or("");
        let pub_bytes = match B64.decode(pub_b64) {
            Ok(b) => b,
            Err(_) => {
                crate::log::warn("handshake: public key is not valid base64");
                return invalidate();
            }
        };

        let pub_key = match rsa::RsaPublicKey::from_pkcs1_der(&pub_bytes).or_else(|_| {
            use rsa::pkcs8::DecodePublicKey;
            rsa::RsaPublicKey::from_public_key_der(&pub_bytes)
        }) {
            Ok(k) => k,
            Err(e) => {
                crate::log::warn(&format!("handshake: bad public key: {e}"));
                return invalidate();
            }
        };

        let shared = SymmetricKey::generate();
        let encrypted = match pub_key.encrypt(
            &mut rand::thread_rng(),
            Oaep::new::<sha1::Sha1>(),
            shared.raw(),
        ) {
            Ok(c) => c,
            Err(e) => {
                crate::log::warn(&format!("handshake: RSA encrypt failed: {e}"));
                return invalidate();
            }
        };

        self.shared = Some(shared);

        crate::log::info(&format!(
            "handshake complete, app={}",
            &app_id[..12.min(app_id.len())]
        ));
        json!({
            "appId": app_id,
            "command": "setupEncryption",
            "messageId": -1,
            "sharedSecret": B64.encode(encrypted),
        })
    }

    fn encrypted(&mut self, app_id: &str, enc_msg: &Value) -> Option<Value> {
        let key = match self.shared.as_ref() {
            Some(k) => k,
            None => {
                crate::log::warn(&format!(
                    "no session for app={}",
                    &app_id[..12.min(app_id.len())]
                ));
                return Some(json!({"appId": app_id, "command": "invalidateEncryption"}));
            }
        };

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
        let resp = self.dispatch(&data, &cmd, mid)?;

        let key = self.shared.as_ref()?;
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

    fn dispatch(&mut self, data: &Value, cmd: &str, mid: i64) -> Option<Value> {
        match cmd {
            "unlockWithBiometricsForUser" => {
                let user_id = data.get("userId").and_then(|u| u.as_str());
                Some(self.handle_unlock(cmd, mid, user_id))
            }
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

    fn handle_unlock(&mut self, cmd: &str, mid: i64, user_id: Option<&str>) -> Value {
        if !self.bridge.owns_user(user_id) {
            crate::log::warn("unlock requested for a different account, refusing");
            return self.reply(cmd, mid, json!({"response": false}));
        }
        match self.bridge.unseal_key() {
            Some(mut key_b64) => {
                crate::log::info("-> unlock granted");
                let resp = self.reply(
                    cmd,
                    mid,
                    json!({"response": true, "userKeyB64": KEY_PLACEHOLDER}),
                );
                self.pending_key = Some(std::mem::take(&mut key_b64));
                resp
            }
            None => {
                crate::log::warn("unlock denied or failed");
                self.reply(cmd, mid, json!({"response": false}))
            }
        }
    }
}

impl Handler for Session {
    fn handle(&mut self, msg: Value) -> Option<Value> {
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
}
