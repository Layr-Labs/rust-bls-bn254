use std::error::Error;
use std::fmt;

use hex::FromHexError;

#[derive(Debug)]
pub enum BLSError {
    SignatureNotInSubgroup,
    SignatureListEmpty,
    PublicKeyNotInSubgroup,
    PublicKeyListEmpty,
}

impl Error for BLSError {}

impl fmt::Display for BLSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BLSError::SignatureNotInSubgroup => write!(f, "Signature not in subgroup"),
            BLSError::PublicKeyNotInSubgroup => write!(f, "Public key not in subgroup"),
            BLSError::SignatureListEmpty => write!(f, "Signature array is empty"),
            BLSError::PublicKeyListEmpty => write!(f, "The public key list is empty"),
        }
    }
}

#[derive(Debug)]
pub enum KeystoreError {
    SerializationError(serde_json::Error),
    HexError(FromHexError),
    GenericError(String),
    DecryptionError(String),
    IoError(std::io::Error),
}

impl Error for KeystoreError {}

impl fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keystore error")
    }
}

impl From<serde_json::Error> for KeystoreError {
    fn from(value: serde_json::Error) -> Self {
        KeystoreError::SerializationError(value)
    }
}

impl From<FromHexError> for KeystoreError {
    fn from(value: FromHexError) -> Self {
        KeystoreError::HexError(value)
    }
}

impl From<std::io::Error> for KeystoreError {
    fn from(value: std::io::Error) -> Self {
        KeystoreError::IoError(value)
    }
    }

impl From<&str> for KeystoreError {
    fn from(value: &str) -> Self {
        KeystoreError::GenericError(value.to_string())
    }
}
