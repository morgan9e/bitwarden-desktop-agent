use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::askpass::Prompter;
use crate::crypto::{enc_string_decrypt_bytes, SymmetricKey};

pub fn login(
    email: &str,
    password: &str,
    server: &str,
    prompt: &Prompter,
) -> (Vec<u8>, String) {
    let base = server.trim_end_matches('/');
    let (api, identity) = if base.contains("bitwarden.com") || base.contains("bitwarden.eu") {
        (
            base.replace("vault.", "api."),
            base.replace("vault.", "identity."),
        )
    } else {
        (format!("{base}/api"), format!("{base}/identity"))
    };

    crate::log::info(&format!("prelogin {api}/accounts/prelogin"));
    let prelogin: serde_json::Value = ureq::post(&format!("{api}/accounts/prelogin"))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"email": email}).to_string())
        .unwrap_or_else(|e| crate::log::fatal(&format!("prelogin failed: {e}")))
        .into_json()
        .unwrap();

    let kdf_type = get_u64(&prelogin, "kdf").unwrap_or(0);
    let kdf_iter = get_u64(&prelogin, "kdfIterations").unwrap_or(600000) as u32;
    let kdf_mem = get_u64(&prelogin, "kdfMemory").unwrap_or(64) as u32;
    let kdf_par = get_u64(&prelogin, "kdfParallelism").unwrap_or(4) as u32;
    crate::log::info(&format!(
        "kdf: {} iterations={kdf_iter}",
        if kdf_type == 0 { "pbkdf2" } else { "argon2id" }
    ));

    crate::log::info("deriving master key...");
    let master_key = Zeroizing::new(derive_master_key(
        password, email, kdf_type, kdf_iter, kdf_mem, kdf_par,
    ));

    let mut pw_hash = {
        let mut buf = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(master_key.as_slice(), password.as_bytes(), 1, &mut buf);
        let h = B64.encode(buf);
        buf.zeroize();
        h
    };

    let device_id = uuid::Uuid::new_v4().to_string();
    let form = [
        ("grant_type", "password"),
        ("username", email),
        ("password", &pw_hash),
        ("scope", "api offline_access"),
        ("client_id", "connector"),
        ("deviceType", "8"),
        ("deviceIdentifier", &device_id),
        ("deviceName", "bw-bridge"),
    ];

    crate::log::info(&format!("token {identity}/connect/token"));
    let token_resp = try_login(&format!("{identity}/connect/token"), &form, prompt);
    pw_hash.zeroize();

    let enc_user_key = extract_encrypted_user_key(&token_resp);
    crate::log::info("decrypting user key...");

    let stretched = stretch(&master_key);
    let user_key = enc_string_decrypt_bytes(&enc_user_key, &stretched)
        .unwrap_or_else(|e| crate::log::fatal(&format!("decrypt user key failed: {e}")));

    let user_id = extract_user_id(
        token_resp
            .get("access_token")
            .and_then(|t| t.as_str())
            .unwrap_or(""),
    );
    crate::log::info(&format!("user key decrypted ({}B)", user_key.len()));

    (user_key.to_vec(), user_id)
}

fn get_u64(v: &serde_json::Value, key: &str) -> Option<u64> {
    v.get(key)
        .or_else(|| {
            let pascal = format!("{}{}", key[..1].to_uppercase(), &key[1..]);
            v.get(&pascal)
        })
        .and_then(|v| v.as_u64())
}

fn get_str<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .or_else(|| {
            let pascal = format!("{}{}", key[..1].to_uppercase(), &key[1..]);
            v.get(&pascal)
        })
        .and_then(|v| v.as_str())
}

fn get_obj<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    v.get(key).or_else(|| {
        let pascal = format!("{}{}", key[..1].to_uppercase(), &key[1..]);
        v.get(&pascal)
    })
}

fn try_login(
    url: &str,
    form: &[(&str, &str)],
    prompt: &Prompter,
) -> serde_json::Value {
    let body: String = form
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencod(v)))
        .collect::<Vec<_>>()
        .join("&");

    match post_form(url, &body) {
        Ok(v) => v,
        Err(e) => {
            if !e.contains("TwoFactor") {
                crate::log::fatal(&format!("login failed: {}", &e[..e.len().min(200)]));
            }
            let body: serde_json::Value =
                serde_json::from_str(&e).unwrap_or(serde_json::Value::Null);
            let providers = get_obj(&body, "twoFactorProviders2").unwrap_or(&serde_json::Value::Null);
            if providers.get("0").is_none() {
                crate::log::fatal("2FA required but TOTP not available");
            }

            crate::log::info("TOTP required");
            let code = prompt("TOTP code:")
                .unwrap_or_else(|| crate::log::fatal("no TOTP code provided"));

            let mut form2: Vec<(&str, &str)> = form.to_vec();
            let trimmed = code.trim().to_string();
            form2.push(("twoFactorToken", &trimmed));
            form2.push(("twoFactorProvider", "0"));

            let body2: String = form2
                .iter()
                .map(|(k, v)| format!("{}={}", k, urlencod(v)))
                .collect::<Vec<_>>()
                .join("&");

            post_form(url, &body2)
                .unwrap_or_else(|e| crate::log::fatal(&format!("login failed: {}", &e[..e.len().min(200)])))
        }
    }
}

fn post_form(url: &str, body: &str) -> Result<serde_json::Value, String> {
    let resp = ureq::post(url)
        .set(
            "Content-Type",
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        .set("Accept", "application/json")
        .set("Device-Type", "8")
        .send_string(body);

    match resp {
        Ok(r) => r.into_json().map_err(|e| e.to_string()),
        Err(ureq::Error::Status(_code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Err(body)
        }
        Err(e) => Err(e.to_string()),
    }
}

fn urlencod(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

fn extract_encrypted_user_key(resp: &serde_json::Value) -> String {
    if let Some(udo) = get_obj(resp, "userDecryptionOptions") {
        if let Some(mpu) = get_obj(udo, "masterPasswordUnlock") {
            if let Some(k) = get_str(mpu, "masterKeyEncryptedUserKey") {
                return k.to_string();
            }
        }
    }
    if let Some(k) = get_str(resp, "key") {
        return k.to_string();
    }
    crate::log::fatal("no encrypted user key in server response");
}

fn extract_user_id(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return "unknown".into();
    }
    let mut payload = parts[1].to_string();
    while payload.len() % 4 != 0 {
        payload.push('=');
    }
    let decoded = B64.decode(&payload).or_else(|_| {
        base64::engine::general_purpose::URL_SAFE.decode(&payload)
    });
    match decoded {
        Ok(bytes) => {
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            v.get("sub")
                .and_then(|s| s.as_str())
                .unwrap_or("unknown")
                .to_string()
        }
        Err(_) => "unknown".into(),
    }
}

fn derive_master_key(
    pw: &str,
    email: &str,
    kdf: u64,
    iters: u32,
    mem: u32,
    par: u32,
) -> Vec<u8> {
    let salt = email.to_lowercase().trim().as_bytes().to_vec();
    match kdf {
        0 => {
            let mut key = vec![0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(pw.as_bytes(), &salt, iters, &mut key);
            key
        }
        1 => {
            let params = argon2::Params::new(mem * 1024, iters, par, Some(32))
                .unwrap_or_else(|e| crate::log::fatal(&format!("argon2 params: {e}")));
            let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let mut key = vec![0u8; 32];
            argon
                .hash_password_into(pw.as_bytes(), &salt, &mut key)
                .unwrap_or_else(|e| crate::log::fatal(&format!("argon2: {e}")));
            key
        }
        _ => crate::log::fatal(&format!("unsupported kdf type: {kdf}")),
    }
}

fn stretch(master_key: &[u8]) -> SymmetricKey {
    let mut enc_hmac = Hmac::<Sha256>::new_from_slice(master_key).unwrap();
    enc_hmac.update(b"enc\x01");
    let enc = enc_hmac.finalize().into_bytes();

    let mut mac_hmac = Hmac::<Sha256>::new_from_slice(master_key).unwrap();
    mac_hmac.update(b"mac\x01");
    let mac = mac_hmac.finalize().into_bytes();

    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&enc);
    combined.extend_from_slice(&mac);
    SymmetricKey::new(combined)
}
