use std::fmt;

#[derive(Debug, Clone)]
pub struct SecureError;

impl fmt::Display for SecureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "security error")
    }
}

impl std::error::Error for SecureError {
    fn description(&self) -> &str {
        "security error"
    }
}

impl From<aes_gcm_siv::Error> for SecureError {
    fn from(_error: aes_gcm_siv::Error) -> Self {
        SecureError
    }
}

impl Default for SecureError {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureError {
    #[must_use]
    pub fn new() -> Self {
        SecureError
    }
}
