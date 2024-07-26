use std::{error::Error, fmt, io};

use hex::FromHexError;
use thiserror::Error as ErrorThis;
use serde_json::Error as SerdeError;

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

#[derive(ErrorThis, Debug)]
pub enum KeystoreError {
    #[error("Invalid KDF function provided.")]
    WrongKdfFunction,
    
    #[error("Serde serialization/deserialization error: {0}")]
    SerdeError(#[from] SerdeError),

    #[error("Hex decode error: {0}")]
    FromHexError(#[from] FromHexError),

    #[error("IO Error error: {0}")]
    IOError(#[from] io::Error),

    #[error("Invalid KDF parameters.")]
    WrongKDFParameters,
    
    #[error("Derive Child Sk Error error: {0}")]
    DeriveChildSkError(String),

    #[error("Derive Master Sk Error error: {0}")]
    DeriveMasterSkError(String),

    #[error("Generic error: {0}")]
    GenericError(String),

    #[error("Scrypt Error: {0}")]
    ScryptError(String),

    #[error("PBKDF2 Error: {0}")]
    PBKDF2Error(String),

    #[error("Encryption Error: {0}")]
    EncryptionError(String),

    #[error("Decryption Error: {0}")]
    DecryptionError(String),

    #[error("Path to nodes Error: {0}")]
    PathToNodes(String),

    #[error("Reconstruct mnemonic Error: {0}")]
    ReconstructMnemonicError(String),

    #[error("Mnemonic Error: {0}")]
    MnemonicError(String),
}

impl KeystoreError {
    // Function to map other errors to GenericError
    pub fn from<E: fmt::Display>(error: E) -> KeystoreError {
        KeystoreError::GenericError(error.to_string())
    }
}

impl From<&str> for KeystoreError {
    fn from(err: &str) -> KeystoreError {
        KeystoreError::GenericError(err.to_string())
    }
}