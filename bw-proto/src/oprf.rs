//! §4.2 oblivious PRF.
//!
//! **Ciphersuite:** RFC 9497 OPRF, `ristretto255-SHA512`, mode `0x00` (base
//! OPRF). Verifiable mode is not used: an AEAD failure already detects a server
//! returning incorrect evaluations, and the client authenticates by device
//! identity so it has no anonymity to protect.
//!
//! This is a thin wrapper over the `voprf` crate and deliberately nothing more.
//! Hand-rolling the construction is the single most dangerous option available
//! here: `curve25519-dalek`'s `RistrettoPoint::hash_from_bytes` is *not* RFC
//! 9380 `hash_to_ristretto255` — it omits the domain separation tag. Using it
//! yields a system that works perfectly end to end, silently disagrees with the
//! RFC test vectors, and provides none of the protection it appears to.
//!
//! **Why the server learns nothing.** `blind` is uniform over the nonzero
//! scalars, so the blinded element is uniform over the group *independently of
//! the PIN*. The transmitted value carries zero bits about the input — not
//! "computationally hidden", literally none.
//!
//! **Why the client cannot proceed alone.** Computing the output requires
//! `k_i`; recovering `k_i` from an evaluation is the discrete logarithm
//! problem. Each round trip yields exactly one candidate evaluation, with no
//! batching or amortisation across guesses. Counting requests is therefore
//! counting guesses, which is the entire point of the construction.

use voprf::{BlindedElement, EvaluationElement, Group, OprfClient, OprfServer, Ristretto255};
use zeroize::Zeroizing;

pub const ELEMENT_LEN: usize = 32;
pub const OUTPUT_LEN: usize = 64;
pub const KEY_LEN: usize = 32;

/// Holds the blinding scalar between `blind` and `finalize`. Zeroized on drop
/// by `voprf`.
pub struct Blinding {
    client: OprfClient<Ristretto255>,
}

/// Client step 1. Returns the state to finalise with and the 32 bytes to send.
pub fn blind(input: &[u8]) -> Result<(Blinding, [u8; ELEMENT_LEN]), String> {
    let result = OprfClient::<Ristretto255>::blind(input, &mut crate::rng::OsRng)
        .map_err(|e| e.to_string())?;
    Ok((
        Blinding {
            client: result.state,
        },
        element_bytes(&result.message.serialize()),
    ))
}

/// Client step 1 with a caller-supplied blinding factor. This exists so the
/// RFC 9497 vectors can be reproduced exactly; nothing in the unlock path may
/// call it, because a predictable blind destroys the whole construction.
pub fn blind_deterministic(
    input: &[u8],
    blind: &[u8; 32],
) -> Result<(Blinding, [u8; ELEMENT_LEN]), String> {
    let scalar = Ristretto255::deserialize_scalar(blind).map_err(|e| e.to_string())?;
    let result = OprfClient::<Ristretto255>::deterministic_blind_unchecked(input, scalar)
        .map_err(|e| e.to_string())?;
    Ok((
        Blinding {
            client: result.state,
        },
        element_bytes(&result.message.serialize()),
    ))
}

impl Blinding {
    /// Client step 3: unblind and hash. `input` must be the same PIN that was
    /// blinded — it is bound into the output, not merely used to select it.
    pub fn finalize(
        &self,
        input: &[u8],
        evaluated: &[u8; ELEMENT_LEN],
    ) -> Result<Zeroizing<[u8; OUTPUT_LEN]>, String> {
        let element =
            EvaluationElement::<Ristretto255>::deserialize(evaluated).map_err(|e| e.to_string())?;
        let output = self
            .client
            .finalize(input, &element)
            .map_err(|e| e.to_string())?;
        let mut out = Zeroizing::new([0u8; OUTPUT_LEN]);
        out.copy_from_slice(&output);
        Ok(out)
    }
}

/// Server: a fresh per-device `k_i`.
pub fn generate_key() -> Zeroizing<[u8; KEY_LEN]> {
    let scalar = Ristretto255::random_scalar(&mut crate::rng::OsRng);
    let bytes = Ristretto255::serialize_scalar(scalar);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&bytes);
    out
}

/// Server step 2: `evaluatedElement = k_i · blindedElement`.
pub fn evaluate(
    key: &[u8; KEY_LEN],
    blinded: &[u8; ELEMENT_LEN],
) -> Result<[u8; ELEMENT_LEN], String> {
    let server = OprfServer::<Ristretto255>::new_with_key(key).map_err(|e| e.to_string())?;
    let element =
        BlindedElement::<Ristretto255>::deserialize(blinded).map_err(|e| e.to_string())?;
    Ok(element_bytes(&server.blind_evaluate(&element).serialize()))
}

fn element_bytes(g: &generic_array::GenericArray<u8, generic_array::typenum::U32>) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(g);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_exchange_agrees_on_the_output() {
        let key = generate_key();
        let (state, blinded) = blind(b"12345678").unwrap();
        let evaluated = evaluate(&key, &blinded).unwrap();
        let a = state.finalize(b"12345678", &evaluated).unwrap();

        let (state2, blinded2) = blind(b"12345678").unwrap();
        // fresh blind ⇒ a different element on the wire, same output
        assert_ne!(blinded, blinded2);
        let evaluated2 = evaluate(&key, &blinded2).unwrap();
        assert_eq!(*a, *state2.finalize(b"12345678", &evaluated2).unwrap());
    }

    #[test]
    fn a_different_key_gives_a_different_output() {
        let (state, blinded) = blind(b"12345678").unwrap();
        let a = state
            .finalize(b"12345678", &evaluate(&generate_key(), &blinded).unwrap())
            .unwrap();
        let b = state
            .finalize(b"12345678", &evaluate(&generate_key(), &blinded).unwrap())
            .unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn finalizing_with_the_wrong_input_gives_a_different_output() {
        let key = generate_key();
        let (state, blinded) = blind(b"12345678").unwrap();
        let evaluated = evaluate(&key, &blinded).unwrap();
        assert_ne!(
            *state.finalize(b"12345678", &evaluated).unwrap(),
            *state.finalize(b"87654321", &evaluated).unwrap()
        );
    }

    #[test]
    fn a_malformed_element_is_rejected() {
        let key = generate_key();
        assert!(evaluate(&key, &[0xff; 32]).is_err());
        let (state, _) = blind(b"pin").unwrap();
        assert!(state.finalize(b"pin", &[0xff; 32]).is_err());
    }
}
