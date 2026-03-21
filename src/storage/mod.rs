pub mod pin;
pub mod sep;

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
        Some("sep") => Box::new(sep::SEPKeyStore::new()),
        None => {
            let s = sep::SEPKeyStore::new();
            if s.is_available() {
                return Box::new(s);
            }
            Box::new(pin::PinKeyStore::new(None))
        }
        Some(other) => crate::log::fatal(&format!("unknown backend: {other}")),
    }
}
