
use voprf::{BlindedElement, EvaluationElement, Group, OprfClient, OprfServer, Ristretto255};
use zeroize::Zeroizing;

pub const ELEMENT_LEN: usize = 32;
pub const OUTPUT_LEN: usize = 64;
pub const KEY_LEN: usize = 32;

pub struct Blinding {
    client: OprfClient<Ristretto255>,
}

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

pub fn generate_key() -> Zeroizing<[u8; KEY_LEN]> {
    let scalar = Ristretto255::random_scalar(&mut crate::rng::OsRng);
    let bytes = Ristretto255::serialize_scalar(scalar);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&bytes);
    out
}

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
