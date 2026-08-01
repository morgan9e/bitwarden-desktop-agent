//! Randomness for key material.
//!
//! Always the OS CSPRNG, never a userspace PRNG (§9.1). A failure here is not
//! recoverable and must not be papered over with a weaker source.

pub fn fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

pub fn bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    fill(&mut buf);
    buf
}

/// Bridges our OS-CSPRNG-only policy into the `rand_core` traits that
/// `x25519-dalek` and `voprf` expect, so there is still exactly one source of
/// key material in the whole system.
pub struct OsRng;

impl rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(bytes())
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(bytes())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for OsRng {}
