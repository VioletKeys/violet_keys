pub use crate::proto::env::Envelope;
use crate::secure::{AesGcmSiv, Crypt};
use crate::secure_error::SecureError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use protobuf::Message;

impl Envelope {
    /// Create a new envelope.
    ///
    /// # Arguments
    /// Key: 256 bit key used to encrypt the data
    /// Data: The data to be encrypted.
    ///
    /// # Errors
    /// If the encryption fails, an error is returned.
    pub fn encrypt(key_id: String, key: [u8; 32], data: &[u8]) -> Result<Self, SecureError> {
        let mut envelope = Self::new();
        envelope.key_id = key_id;
        envelope.crypt_data = AesGcmSiv::encrypt(key, data)?;
        Ok(envelope)
    }

    /// Decrypt the envelope.
    ///
    /// # Arguments
    /// Key: 256 bit key used to encrypt the data
    ///
    /// # Errors
    /// If the decryption fails, an error is returned.
    pub fn decrypt(&self, key: [u8; 32]) -> Result<Vec<u8>, SecureError> {
        let data = AesGcmSiv::decrypt(key, self.crypt_data.as_slice())?;
        Ok(data)
    }

    /// Convert an envelope to base64.
    ///
    /// # Errors
    /// Throws an error if the conversion to bytes fails.
    pub fn to_base64(&self) -> Result<String, SecureError> {
        let bytes = self.write_to_bytes()?;
        Ok(STANDARD.encode(bytes.as_slice()))
    }

    /// Parse an envelope from base64.
    ///
    /// # Errors
    /// Throws an error if the base64 string is invalid, or the parsing into an envelope fails.
    pub fn from_base64(base64: &str) -> Result<Self, SecureError> {
        let bytes = STANDARD.decode(base64).map_err(|_| SecureError)?;
        Envelope::parse_from_bytes(bytes.as_slice()).map_err(|_| SecureError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_envelope() {
        let key = crate::secure::generate_key();

        let data = b"Hello, world!";
        let envelope = Envelope::encrypt("key.id.123".to_string(), key, data);
        let decrypted_data = envelope.unwrap().decrypt(key).unwrap();
        assert_eq!(data, decrypted_data.as_slice());
    }

    #[test]
    fn test_envelope_base64() {
        let key = crate::secure::generate_key();

        let data = b"Hello, world!";
        let envelope = Envelope::encrypt("key.id.123".to_string(), key, data);
        let base64 = envelope.unwrap().to_base64().unwrap();
        let envelope = Envelope::from_base64(&base64).unwrap();
        let decrypted_data = envelope.decrypt(key).unwrap();
        assert_eq!(data, decrypted_data.as_slice());
    }
}
