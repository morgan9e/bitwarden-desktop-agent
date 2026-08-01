
use std::fmt;

use zeroize::Zeroizing;

use crate::askpass::Prompter;
use crate::blob::{self, Blob};
use crate::device::{self, Device};
use crate::kdf;
use crate::net::{self, NetError};

pub enum UnlockError {
    Cancelled,
    NotEnrolled,
    Failed,
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
        crate::log::error(&format!("finalize: {e}"));
        UnlockError::Failed
    })?;
    Ok(Some(output))
}
