
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

    crate::log::info(if blob::exists(&blob_path) {
        "re-enrolling"
    } else {
        "enrolling"
    });
    crate::log::info(&format!("state directory: {}", dir.display()));

    // Log in before touching the server, so a bad password or TOTP doesn't spend the token.
    let mut pw = match password {
        Some(p) => p,
        None => prompt("master password:").ok_or("no password provided")?,
    };
    crate::log::info(&format!("logging in as {email}"));
    let (mut user_key, user_id) = crate::auth::login(email, &pw, vault, prompt);
    pw.zeroize();
    crate::log::info(&format!("authenticated, uid={user_id}"));

    let result = seal(&user_key, &user_id, email, label, server, prompt).map(|_| ());
    user_key.zeroize();
    result
}

pub(crate) fn seal(
    user_key: &[u8],
    user_id: &str,
    email: &str,
    label: &str,
    server: Option<ServerEnrollment>,
    prompt: &Prompter,
) -> Result<Device, String> {
    let blob_path = bw_proto::paths::blob_path();
    let device_path = bw_proto::paths::device_path();
    let existing = Device::load(&device_path).ok();

    // Before registering, so a mistyped confirmation doesn't spend the token either.
    let pin = prompt_new_pin(prompt)?;

    let (device_id, binding) = match &server {
        // The server never reuses a device id or static key, so every
        // registration gets fresh ones. Nothing is written until it succeeds.
        Some(s) => {
            let device_id = new_device_id();
            let binding = register(s, &device_id, label)?;
            (device_id, Some(binding))
        }
        // Re-sealing keeps the device's existing server binding: the blob
        // key must include the OPRF output whenever unlock will ask for it.
        None => {
            let device_id = existing
                .as_ref()
                .map(|d| d.device_id.clone())
                .unwrap_or_else(new_device_id);
            let binding = match &existing {
                Some(d) => unlock::ServerKey::for_device(d)?,
                None => None,
            };
            (device_id, binding)
        }
    };

    let salt: [u8; SALT_LEN] = bw_proto::rng::bytes();
    let oprf = unlock::oprf_output(binding.as_ref(), &pin).map_err(|e| match (&server, &binding) {
        (None, Some(b)) => format!("{e} (to register with {} again, pass --server and --token)", b.addr),
        _ => e.to_string(),
    })?;

    crate::log::info("deriving blob key (scrypt, ~0.5 s)...");
    let scrypt_out = kdf::scrypt_pin(&pin, &salt)?;
    let k = kdf::derive_blob_key(&scrypt_out, oprf.as_deref(), &salt);

    if let (Some(_), Some(b)) = (&server, &binding) {
        device::save_identity(&b.identity)?;
    }
    blob::write(&blob_path, &salt, user_key, &k)?;

    let device = Device {
        device_id,
        user_id: user_id.to_string(),
        email: email.to_string(),
        label: label.to_string(),
        server: binding.as_ref().map(|b| b.addr.clone()),
        server_pub: binding.as_ref().map(|b| B64.encode(b.public)),
    };
    device.save(&device_path)?;
    crate::log::info(&format!("enrolled device {}", device.device_id));

    if let Some(old) = existing.filter(|d| d.server.is_some() && d.device_id != device.device_id) {
        crate::log::warn(&format!(
            "the previous device {} may still be registered: run `bw-keyctl revoke {}` on the server",
            old.device_id, old.device_id
        ));
    }
    Ok(device)
}

fn register(s: &ServerEnrollment, device_id: &str, label: &str) -> Result<unlock::ServerKey, String> {
    let token = bw_proto::token::Token::decode(&s.token)?;
    let identity = Zeroizing::new(bw_proto::noise::generate_private_key());
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
    Ok(unlock::ServerKey {
        addr: s.addr.clone(),
        public: token.server_pub,
        identity,
    })
}

pub fn change_pin(prompt: &Prompter) -> Result<(), String> {
    let blob_path = bw_proto::paths::blob_path();
    if !blob::exists(&blob_path) {
        return Err("not enrolled".into());
    }
    let old = Blob::read(&blob_path)?;
    let salt = *old.salt();

    let server = match Device::load(&bw_proto::paths::device_path()) {
        Ok(d) => unlock::ServerKey::for_device(&d)?,
        Err(_) => None,
    };
    if server.is_some() {
        crate::log::warn("changing the PIN costs two attempts from this device's budget");
    }

    let current = Zeroizing::new(prompt("current PIN:").ok_or("no PIN provided")?);
    let oprf = unlock::oprf_output(server.as_ref(), &current).map_err(|e| e.to_string())?;
    let scrypt_out = kdf::scrypt_pin(&current, &salt)?;
    let k = kdf::derive_blob_key(&scrypt_out, oprf.as_deref(), &salt);
    let user_key = old.decrypt(&k).map_err(|_| "unlock failed".to_string())?;

    let pin = prompt_new_pin(prompt)?;
    let oprf = unlock::oprf_output(server.as_ref(), &pin).map_err(|e| e.to_string())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetError;
    use crate::testutil::{scripted, KeyServer, StateDir};
    use crate::unlock::{UnlockError, Unlocker};

    const USER_KEY: [u8; blob::USER_KEY_LEN] = [0x5a; blob::USER_KEY_LEN];

    fn seal_with(pin: &str, server: Option<ServerEnrollment>) -> Result<Device, String> {
        seal(&USER_KEY, "user-1", "a@example.com", "test", server, &scripted(&[pin, pin]))
    }

    fn unlock_with(pin: &str) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
        let device = Device::load(&bw_proto::paths::device_path()).unwrap();
        Unlocker::new(device, scripted(&[pin])).unlock()
    }

    #[test]
    fn resealing_without_a_server_keeps_the_existing_binding() {
        let _state = StateDir::new("reseal");
        let server = KeyServer::start("reseal");
        let first = seal_with("11111111", Some(server.enrollment("laptop"))).unwrap();
        assert_eq!(&unlock_with("11111111").unwrap()[..], &USER_KEY);

        let second = seal_with("22222222", None).unwrap();
        assert_eq!(second.device_id, first.device_id);
        assert_eq!(second.server, first.server);
        assert_eq!(second.server_pub, first.server_pub);
        assert_eq!(&unlock_with("22222222").unwrap()[..], &USER_KEY);
        assert!(matches!(unlock_with("11111111"), Err(UnlockError::Failed)));
    }

    #[test]
    fn re_enrolling_after_a_revoke_registers_a_fresh_device() {
        let _state = StateDir::new("revoke");
        let server = KeyServer::start("revoke");
        let first = seal_with("11111111", Some(server.enrollment("laptop"))).unwrap();
        let first_identity = std::fs::read(bw_proto::paths::identity_path()).unwrap();

        server.revoke(&first.device_id);
        assert!(matches!(
            unlock_with("11111111"),
            Err(UnlockError::Server(NetError::Denied))
        ));

        let second = seal_with("22222222", Some(server.enrollment("laptop"))).unwrap();
        assert_ne!(second.device_id, first.device_id);
        assert_ne!(
            std::fs::read(bw_proto::paths::identity_path()).unwrap(),
            first_identity
        );
        assert_eq!(&unlock_with("22222222").unwrap()[..], &USER_KEY);
    }

    #[test]
    fn a_rejected_registration_leaves_the_enrolled_device_untouched() {
        let _state = StateDir::new("rejected");
        let server = KeyServer::start("rejected");
        let enrollment = server.enrollment("laptop");
        let spent = ServerEnrollment {
            addr: enrollment.addr.clone(),
            token: enrollment.token.clone(),
        };
        let first = seal_with("11111111", Some(enrollment)).unwrap();
        let identity = std::fs::read(bw_proto::paths::identity_path()).unwrap();

        assert!(seal_with("22222222", Some(spent)).is_err());
        assert_eq!(
            Device::load(&bw_proto::paths::device_path()).unwrap().device_id,
            first.device_id
        );
        assert_eq!(std::fs::read(bw_proto::paths::identity_path()).unwrap(), identity);
        assert_eq!(&unlock_with("11111111").unwrap()[..], &USER_KEY);
    }

    #[test]
    fn a_pin_mismatch_does_not_spend_the_token() {
        let _state = StateDir::new("mismatch");
        let server = KeyServer::start("mismatch");
        let enrollment = server.enrollment("laptop");
        let retry = ServerEnrollment {
            addr: enrollment.addr.clone(),
            token: enrollment.token.clone(),
        };

        let mismatched = seal(
            &USER_KEY,
            "user-1",
            "a@example.com",
            "test",
            Some(enrollment),
            &scripted(&["11111111", "11111112"]),
        );
        assert!(mismatched.is_err());
        seal_with("11111111", Some(retry)).unwrap();
    }
}
