pub mod pin;

pub trait KeyStore {
    fn name(&self) -> &str;
    fn is_available(&self) -> bool;
    fn has_key(&self, uid: &str) -> bool;
    fn store(&self, uid: &str, data: &[u8], auth: &str) -> Result<(), String>;
    fn load(&self, uid: &str, auth: &str) -> Result<Vec<u8>, String>;
    fn remove(&self, uid: &str);
}

pub fn get_backend(preferred: Option<&str>) -> Box<dyn KeyStore> {
    match preferred {
        Some("pin") => Box::new(pin::PinKeyStore::new(None)),
        _ => Box::new(pin::PinKeyStore::new(None)),
    }
}
