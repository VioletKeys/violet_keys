use crate::secure::{AesGcmSiv, Crypt};
use crate::secure_error::SecureError;

struct Envelope {
    id: String,
    crypt_data: Vec<u8>,
}

impl Envelope {
    pub fn new(key_type: String, key: [u8; 32], data: &[u8]) -> Self {
        let crypt_data = AesGcmSiv::encrypt(key, data).unwrap();
        Self {
            id: key_type,
            crypt_data,
        }
    }

    pub fn decrypt(&self, key: [u8; 32]) -> Result<Vec<u8>, SecureError> {
        let data = AesGcmSiv::decrypt(key, self.crypt_data.as_slice())?;
        Ok(data)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope() {
        let key = crate::secure::generate_key();

        let data = b"Hello, world!";
        let envelope = Envelope::new("key.id.123".to_string(), key, data);
        let decrypted_data = envelope.decrypt(key).unwrap();
        assert_eq!(data, decrypted_data.as_slice());
    }
}