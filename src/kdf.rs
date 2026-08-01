//! §4.1 key derivation.
//!
//! ```text
//! K = HKDF-SHA256(
//!       ikm  = scrypt(PIN, salt, N=2^17, r=8, p=1, dkLen=32) ‖ oprf_output,
//!       salt = salt,
//!       info = "bw-agent/v2/blob",
//!       L    = 32
//!     )
//! ```
//!
//! Two independent inputs, each covering the other's failure mode. `oprf_output`
//! requires the server and is what makes offline guessing impossible; scrypt is
//! purely local and is the backstop for a leaked `k_i`. Neither alone suffices
//! and neither is redundant.

use hkdf::Hkdf;
use scrypt::{scrypt, Params};
use sha2::Sha256;
use zeroize::Zeroizing;

const SCRYPT_LOG_N: u8 = 17; // 128 MiB
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const INFO: &[u8] = b"bw-agent/v2/blob";

pub const SCRYPT_OUT_LEN: usize = 32;
pub const OPRF_OUT_LEN: usize = 64;

/// ~0.5 s and 128 MiB. Run this concurrently with the server round trip to hide
/// the latency, but never cache the result across attempts.
pub fn scrypt_pin(pin: &str, salt: &[u8]) -> Result<Zeroizing<[u8; SCRYPT_OUT_LEN]>, String> {
    let params =
        Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_OUT_LEN).map_err(|e| e.to_string())?;
    let mut out = Zeroizing::new([0u8; SCRYPT_OUT_LEN]);
    scrypt(pin.as_bytes(), salt, &params, out.as_mut()).map_err(|e| e.to_string())?;
    Ok(out)
}

/// `oprf_output` is `None` only before the OPRF is wired up (build phase 1).
/// Blobs written without it do not decrypt with it, and vice versa.
pub fn derive_blob_key(
    scrypt_out: &[u8; SCRYPT_OUT_LEN],
    oprf_output: Option<&[u8; OPRF_OUT_LEN]>,
    salt: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(SCRYPT_OUT_LEN + OPRF_OUT_LEN));
    ikm.extend_from_slice(scrypt_out);
    if let Some(o) = oprf_output {
        ikm.extend_from_slice(o);
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut k = Zeroizing::new([0u8; 32]);
    hk.expand(INFO, k.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oprf_output_changes_the_derived_key() {
        let s = [1u8; SCRYPT_OUT_LEN];
        let salt = [2u8; 32];
        let without = derive_blob_key(&s, None, &salt);
        let with = derive_blob_key(&s, Some(&[3u8; OPRF_OUT_LEN]), &salt);
        assert_ne!(*without, *with);
    }

    #[test]
    fn salt_changes_the_derived_key() {
        let s = [1u8; SCRYPT_OUT_LEN];
        let o = [3u8; OPRF_OUT_LEN];
        assert_ne!(
            *derive_blob_key(&s, Some(&o), &[2u8; 32]),
            *derive_blob_key(&s, Some(&o), &[9u8; 32])
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let s = [1u8; SCRYPT_OUT_LEN];
        let o = [3u8; OPRF_OUT_LEN];
        assert_eq!(
            *derive_blob_key(&s, Some(&o), &[2u8; 32]),
            *derive_blob_key(&s, Some(&o), &[2u8; 32])
        );
    }
}
