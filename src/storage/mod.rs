pub mod pin;
#[cfg(target_os = "linux")]
pub mod tpm2;

pub trait KeyStore {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn has_key(&self, uid: &str) -> bool;
    fn store(&self, uid: &str, data: &[u8], auth: &str) -> Result<(), String>;
    fn load(&self, uid: &str, auth: &str) -> Result<Vec<u8>, String>;
    fn remove(&self, uid: &str);
    fn find_key(&self) -> Option<String>;
}

pub fn get_backend(preferred: Option<&str>) -> Box<dyn KeyStore> {
    match preferred {
        Some("pin") => Box::new(pin::PinKeyStore::new(None)),
        #[cfg(target_os = "linux")]
        Some("tpm2") => Box::new(tpm2::Tpm2KeyStore::new(None)),
        None => {
            let pin = pin::PinKeyStore::new(None);
            #[cfg(target_os = "linux")]
            {
                let tpm = tpm2::Tpm2KeyStore::new(None);
                // if keys already exist, use whichever backend owns them
                if tpm.find_key().is_some() {
                    return Box::new(tpm);
                }
                if pin.find_key().is_some() {
                    return Box::new(pin);
                }
                // no existing keys — prefer TPM2 if available
                if tpm.is_available() {
                    return Box::new(tpm);
                }
            }
            Box::new(pin)
        }
        Some(other) => crate::log::fatal(&format!("unknown backend: {other}")),
    }
}
