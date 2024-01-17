use crate::secure_error::SecureError;
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::rand_core::RngCore;
/// Provides for default en/decryption utilities.
/// Uses AES-GCM-SIV with 256 bit keys, and 96 bit nonce.
/// Current implementation assumes no AAD usage.
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256GcmSiv, Nonce,
};

const EMPTY_ARRAY: &[u8; 0] = &[];

/// Encrypt a message with a key.
/// Returns the nonce and the encrypted data.
///
/// # Arguments
/// Key: 256 bit key used to encrypt the data
/// Data: The data to be encrypted.
///
/// # Returns
/// A vector of bytes containing the nonce and the encrypted data.
///
/// # Errors
/// If the encryption fails, an error is returned.
pub fn encrypt(key: [u8; 32], data: &[u8]) -> Result<Vec<u8>, SecureError> {
    let mut nonce = [0u8; 12]; // 96-bits; unique per message
    OsRng.fill_bytes(&mut nonce);
    let payload = Payload {
        msg: data,
        aad: EMPTY_ARRAY,
    };
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
    let cipher_data = cipher.encrypt(Nonce::from_slice(&nonce), payload)?;
    let mut result = vec![0u8; 12 + cipher_data.len()];
    result[0..12].copy_from_slice(&nonce);
    result[12..].copy_from_slice(&cipher_data);
    Ok(result)
}

/// Decrypt a message with a key.
///
/// # Arguments
/// Key: 256 bit key used to encrypt the data
/// Crypt: The data to be decrypted.
///
/// # Returns
/// A vector of bytes containing the decrypted data.
///
/// # Errors
/// If the decryption fails, an error is returned.
pub fn decrypt(key: [u8; 32], crypt: &[u8]) -> Result<Vec<u8>, SecureError> {
    if crypt.len() < 13 {
        return Err(SecureError);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&crypt[0..12]);
    let cipher_data = &crypt[12..];
    let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
    let payload = Payload {
        msg: cipher_data,
        aad: EMPTY_ARRAY,
    };
    Ok(cipher.decrypt(Nonce::from_slice(&nonce), payload)?)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn encrypt_decrypt_bad_key() {
        let mut key = [0u8; 32];
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7];
        OsRng.fill_bytes(&mut key);
        let crypt = encrypt(key, data.as_slice()).unwrap();
        assert_ne!(data, crypt); // check the full response
        let cipher_data = crypt[12..].to_vec();
        assert_ne!(data, cipher_data); // check what we know to be the cipher data
        key[0] = key[0] + 1;
        let data2 = decrypt(key, crypt.as_slice());
        assert!(data2.is_err()); //results should be good.
    }

    #[test]
    fn encrypt_decrypt_empty_test() {
        let mut key = [0u8; 32];
        let data = vec![];
        OsRng.fill_bytes(&mut key);
        let crypt = encrypt(key, data.as_slice()).unwrap();
        assert_ne!(data, crypt); // check the full response
        let cipher_data = crypt[12..].to_vec();
        assert_ne!(data, cipher_data); // check what we know to be the cipher data
        let data2 = decrypt(key, crypt.as_slice()).unwrap();
        assert_eq!(data2, data); //results should be good.
    }

    #[test]
    fn encrypt_decrypt_test() {
        let mut key = [0u8; 32];
        let data = vec![0, 1, 2, 3, 4, 5, 6, 7];
        OsRng.fill_bytes(&mut key);
        let crypt = encrypt(key, data.as_slice()).unwrap();
        assert_ne!(data, crypt); // check the full response
        let cipher_data = crypt[12..].to_vec();
        assert_ne!(data, cipher_data); // check what we know to be the cipher data
        let data2 = decrypt(key, crypt.as_slice()).unwrap();
        assert_eq!(data2, data); //results should be good.
    }

    /// Test the AES/GCM/SIV implementation.
    #[test]
    fn it_works() {
        let key = Aes256GcmSiv::generate_key(&mut OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
        let cipher_data = cipher
            .encrypt(nonce, b"datatext message".as_ref())
            .expect("encryption failure!");
        let datatext = cipher
            .decrypt(nonce, cipher_data.as_ref())
            .expect("decryption failure!");
        assert_eq!(&datatext, b"datatext message");
    }
}
