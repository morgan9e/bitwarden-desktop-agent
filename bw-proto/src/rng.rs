
pub fn fill(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

pub fn bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    fill(&mut buf);
    buf
}

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
