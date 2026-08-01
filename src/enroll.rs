
use zeroize::{Zeroize, Zeroizing};

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::askpass::Prompter;
use crate::blob::{self, Blob, SALT_LEN};
use crate::device::{self, new_device_id, Device};
use crate::kdf;
use crate::net;
use crate::unlock;

const RECOMMENDED_PIN_LEN: usize = 8;
const MIN_PIN_LEN: usize = 4;

pub struct ServerEnrollment {
    pub addr: String,
    pub token: String,
}

pub fn enroll(
    email: &str,
    vault: &str,
    password: Option<String>,
    label: &str,
    server: Option<ServerEnrollment>,
    prompt: &Prompter,
) -> Result<(), String> {
    let dir = bw_proto::paths::ensure_state_dir().map_err(|e| e.to_string())?;
    let blob_path = bw_proto::paths::blob_path();
    let device_path = bw_proto::paths::device_path();

    crate::log::info(if blob::exists(&blob_path) {
        "re-enrolling"
    } else {
        "enrolling"
    });
    crate::log::info(&format!("state directory: {}", dir.display()));

    let existing = Device::load(&device_path).ok();
    let device_id = existing
        .as_ref()
        .map(|d| d.device_id.clone())
        .unwrap_or_else(new_device_id);

    let registered = match &server {
        Some(s) => Some(register(s, &device_id, label)?),
        None => None,
    };

    let mut pw = match password {
        Some(p) => p,
        None => prompt("master password:").ok_or("no password provided")?,
    };
    crate::log::info(&format!("logging in as {email}"));
    let (mut user_key, user_id) = crate::auth::login(email, &pw, vault, prompt);
    pw.zeroize();
    crate::log::info(&format!("authenticated, uid={user_id}"));

    let result = (|| -> Result<(), String> {
        let pin = prompt_new_pin(prompt)?;
        let salt: [u8; SALT_LEN] = bw_proto::rng::bytes();

        let server = registered.as_ref().map(|(addr, key)| (addr.as_str(), *key));
        let oprf = unlock::oprf_output(server, &pin).map_err(|e| e.to_string())?;

        crate::log::info("deriving blob key (scrypt, ~0.5 s)...");
        let scrypt_out = kdf::scrypt_pin(&pin, &salt)?;
        let k = kdf::derive_blob_key(&scrypt_out, oprf.as_deref(), &salt);

        blob::write(&blob_path, &salt, &user_key, &k)?;

        let (addr, server_pub) = match &registered {
            Some((addr, key)) => (Some(addr.clone()), Some(B64.encode(key))),
            None => (
                existing.as_ref().and_then(|d| d.server.clone()),
                existing.as_ref().and_then(|d| d.server_pub.clone()),
            ),
        };
        let device = Device {
            device_id: device_id.clone(),
            user_id: user_id.clone(),
            email: email.to_string(),
            label: label.to_string(),
            server: addr,
            server_pub,
        };
        device.save(&device_path)?;
        crate::log::info(&format!("enrolled device {}", device.device_id));
        Ok(())
    })();

    user_key.zeroize();
    result
}

fn register(s: &ServerEnrollment, device_id: &str, label: &str) -> Result<(String, [u8; 32]), String> {
    let token = bw_proto::token::Token::decode(&s.token)?;
    let identity = device::load_or_create_identity()?;
    let static_pub = bw_proto::noise::public_key(&identity);

    crate::log::info(&format!("enrolling with {}", s.addr));
    net::enroll(
        &s.addr,
        &token.server_pub,
        &s.token,
        &static_pub,
        device_id,
        label,
    )
    .map_err(|e| e.to_string())?;
    crate::log::info(&format!("server accepted device {device_id}"));
    Ok((s.addr.clone(), token.server_pub))
}

pub fn change_pin(prompt: &Prompter) -> Result<(), String> {
    let blob_path = bw_proto::paths::blob_path();
    if !blob::exists(&blob_path) {
        return Err("not enrolled".into());
    }
    let old = Blob::read(&blob_path)?;
    let salt = *old.salt();

    let device = Device::load(&bw_proto::paths::device_path()).ok();
    let server_pub = match device.as_ref().filter(|d| d.server.is_some()) {
        Some(d) => Some(device::server_public(d)?),
        None => None,
    };
    let server = |key: &Option<[u8; 32]>| match (device.as_ref().and_then(|d| d.server.as_deref()), key) {
        (Some(addr), Some(k)) => Some((addr, *k)),
        _ => None,
    };
    if server_pub.is_some() {
        crate::log::warn("changing the PIN costs two attempts from this device's budget");
    }

    let current = Zeroizing::new(prompt("current PIN:").ok_or("no PIN provided")?);
    let oprf = unlock::oprf_output(server(&server_pub), &current).map_err(|e| e.to_string())?;
    let scrypt_out = kdf::scrypt_pin(&current, &salt)?;
    let k = kdf::derive_blob_key(&scrypt_out, oprf.as_deref(), &salt);
    let user_key = old.decrypt(&k).map_err(|_| "unlock failed".to_string())?;

    let pin = prompt_new_pin(prompt)?;
    let oprf = unlock::oprf_output(server(&server_pub), &pin).map_err(|e| e.to_string())?;
    let scrypt_out = kdf::scrypt_pin(&pin, &salt)?;
    let k = kdf::derive_blob_key(&scrypt_out, oprf.as_deref(), &salt);
    blob::write(&blob_path, &salt, &user_key, &k)?;
    crate::log::info("PIN changed");
    Ok(())
}

pub fn remove() -> Result<(), String> {
    let device = Device::load(&bw_proto::paths::device_path()).ok();
    for path in [
        bw_proto::paths::blob_path(),
        bw_proto::paths::identity_path(),
        bw_proto::paths::device_path(),
    ] {
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            crate::log::info(&format!("removed {}", path.display()));
        }
    }
    if let Some(d) = device {
        if d.server.is_some() {
            crate::log::warn(&format!(
                "server-side state remains: run `bw-keyctl revoke {}` on the server",
                d.device_id
            ));
        }
    }
    Ok(())
}

pub fn status() {
    let dir = bw_proto::paths::state_dir();
    println!("state directory : {}", dir.display());
    println!(
        "blob            : {}",
        if blob::exists(&bw_proto::paths::blob_path()) {
            "present"
        } else {
            "absent (not enrolled)"
        }
    );
    match Device::load(&bw_proto::paths::device_path()) {
        Ok(d) => {
            println!("device_id       : {}", d.device_id);
            println!("account         : {} ({})", d.email, d.user_id);
            println!("label           : {}", d.label);
            println!("server          : {}", d.server.as_deref().unwrap_or("none"));
        }
        Err(_) => println!("device.toml     : absent"),
    }
    println!("socket          : {}", bw_proto::paths::socket_path().display());
}

fn prompt_new_pin(prompt: &Prompter) -> Result<Zeroizing<String>, String> {
    let pin = Zeroizing::new(prompt("choose PIN:").ok_or("no PIN provided")?);
    let confirm = Zeroizing::new(prompt("confirm PIN:").ok_or("no PIN provided")?);
    if *pin != *confirm {
        return Err("PINs don't match".into());
    }
    if pin.chars().count() < MIN_PIN_LEN {
        return Err(format!("PIN must be at least {MIN_PIN_LEN} characters"));
    }
    if pin.chars().count() < RECOMMENDED_PIN_LEN {
        crate::log::warn(&format!(
            "PIN is shorter than the recommended {RECOMMENDED_PIN_LEN} characters"
        ));
    }
    Ok(pin)
}
