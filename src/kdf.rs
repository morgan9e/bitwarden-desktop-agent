
use hkdf::Hkdf;
use scrypt::{scrypt, Params};
use sha2::Sha256;
use zeroize::Zeroizing;

const SCRYPT_LOG_N: u8 = 17;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;
const INFO: &[u8] = b"bw-agent/v2/blob";

pub const SCRYPT_OUT_LEN: usize = 32;
pub const OPRF_OUT_LEN: usize = 64;

pub fn scrypt_pin(pin: &str, salt: &[u8]) -> Result<Zeroizing<[u8; SCRYPT_OUT_LEN]>, String> {
    let params =
        Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, SCRYPT_OUT_LEN).map_err(|e| e.to_string())?;
    let mut out = Zeroizing::new([0u8; SCRYPT_OUT_LEN]);
    scrypt(pin.as_bytes(), salt, &params, out.as_mut()).map_err(|e| e.to_string())?;
    Ok(out)
}

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
