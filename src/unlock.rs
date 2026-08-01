//! The unlock path: PIN → blob key → Bitwarden user key.
//!
//! §5.3, steps 2–12:
//!
//! ```text
//!  2. prompt PIN via askpass
//!  3. blindedElement = Blind(PIN)
//!  4. → server   eval{blinded}
//!  5. server     consume budget, COMMIT + fsync
//!  6. server     evaluatedElement = k_i · blindedElement
//!  7. ← server   ok{evaluated}
//!  8. oprf_output = Finalize(...)
//!  9. K = HKDF(scrypt(PIN) ‖ oprf_output)
//! 10. decrypt blob → user_key
//! 12. zeroize all intermediates
//! ```
//!
//! Step 9's scrypt costs ~0.5 s, so it runs concurrently with steps 4–7 to hide
//! the latency. It is never cached across attempts.

use std::fmt;

use zeroize::Zeroizing;

use crate::askpass::Prompter;
use crate::blob::{self, Blob};
use crate::device::{self, Device};
use crate::kdf;
use crate::net::{self, NetError};

pub enum UnlockError {
    /// No PIN entered — the user dismissed the prompt.
    Cancelled,
    /// No blob on disk.
    NotEnrolled,
    /// Wrong PIN, corrupted blob, AEAD failure. Deliberately one bucket (§9.3):
    /// distinguishing them tells an attacker which of the two they got wrong.
    Failed,
    /// Operational, and safe to describe precisely — the fallback is always the
    /// master password, and no vault data is at risk on any of these paths.
    Server(NetError),
}

impl fmt::Display for UnlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "cancelled"),
            Self::NotEnrolled => write!(f, "not enrolled — run `bw-agent enroll`"),
            Self::Failed => write!(f, "unlock failed"),
            Self::Server(e) => write!(f, "{e}"),
        }
    }
}

pub struct Unlocker {
    device: Device,
    prompt: Prompter,
}

impl Unlocker {
    pub fn new(device: Device, prompt: Prompter) -> Self {
        Self { device, prompt }
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    pub fn unlock(&self) -> Result<Zeroizing<Vec<u8>>, UnlockError> {
        let path = bw_proto::paths::blob_path();
        if !blob::exists(&path) {
            return Err(UnlockError::NotEnrolled);
        }
        let blob = Blob::read(&path).map_err(|e| {
            crate::log::error(&format!("blob unreadable: {e}"));
            UnlockError::Failed
        })?;
        let salt = *blob.salt();

        let pin = Zeroizing::new((self.prompt)("Enter PIN:").ok_or(UnlockError::Cancelled)?);

        // scrypt (~0.5 s, 128 MiB) runs while the server round trip is in
        // flight. Both must succeed; neither result is reused.
        let scrypt_job = {
            let pin = pin.clone();
            std::thread::spawn(move || kdf::scrypt_pin(&pin, &salt))
        };

        let oprf_output = self.oprf_round_trip(&pin);

        let scrypt_out = scrypt_job
            .join()
            .map_err(|_| UnlockError::Failed)?
            .map_err(|e| {
                crate::log::error(&format!("scrypt: {e}"));
                UnlockError::Failed
            })?;

        let oprf_output = oprf_output?;

        let k = kdf::derive_blob_key(&scrypt_out, oprf_output.as_deref(), &salt);
        blob.decrypt(&k).map_err(|_| UnlockError::Failed)
    }

    fn oprf_round_trip(
        &self,
        pin: &str,
    ) -> Result<Option<Zeroizing<[u8; kdf::OPRF_OUT_LEN]>>, UnlockError> {
        let server = match self.device.server.as_deref() {
            Some(addr) => Some((
                addr,
                device::server_public(&self.device).map_err(|e| {
                    crate::log::error(&e);
                    UnlockError::Failed
                })?,
            )),
            None => None,
        };
        oprf_output(server, pin)
    }
}

/// One OPRF round trip, and therefore exactly one guess against the device's
/// budget. `None` when this device enrolled without a server: the blob key then
/// comes from scrypt alone, and offline guessing is not bounded.
pub fn oprf_output(
    server: Option<(&str, [u8; 32])>,
    pin: &str,
) -> Result<Option<Zeroizing<[u8; kdf::OPRF_OUT_LEN]>>, UnlockError> {
    let Some((addr, server_pub)) = server else {
        return Ok(None);
    };

    let identity = device::load_or_create_identity().map_err(|e| {
        crate::log::error(&e);
        UnlockError::Failed
    })?;

    let (state, blinded) = bw_proto::oprf::blind(pin.as_bytes()).map_err(|e| {
        crate::log::error(&format!("blind: {e}"));
        UnlockError::Failed
    })?;

    let (evaluated, tokens_left) =
        net::eval(addr, &server_pub, &identity, &blinded).map_err(UnlockError::Server)?;
    crate::log::info(&format!("server granted the attempt, {tokens_left} left"));

    let output = state.finalize(pin.as_bytes(), &evaluated).map_err(|e| {
        // A server returning a wrong evaluation lands here or, more likely, as
        // an AEAD failure downstream. Verifiable mode buys nothing over that.
        crate::log::error(&format!("finalize: {e}"));
        UnlockError::Failed
    })?;
    Ok(Some(output))
}
