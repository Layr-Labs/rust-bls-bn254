use std::fmt;

use hex::FromHexError;
use serde_json::Error as SerdeError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BLSError {
    #[error("Signature not in subgroup")]
    SignatureNotInSubgroup,
    #[error("Signature array is empty")]
    SignatureListEmpty,
    #[error("Public key not in subgroup")]
    PublicKeyNotInSubgroup,
    #[error("The public key list is empty")]
    PublicKeyListEmpty,
}

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Invalid KDF function provided")]
    WrongKdfFunction,

    #[error("Invalid KDF parameters")]
    WrongKDFParameters,

    #[error(transparent)]
    SerdeError(#[from] SerdeError),

    #[error(transparent)]
    FromHexError(#[from] FromHexError),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error("Failed to derive child secret key: {0}")]
    DeriveChildSkError(String),

    #[error("Failed to derive master secret key: {0}")]
    DeriveMasterSkError(String),

    #[error("{0}")]
    GenericError(String),

    #[error("Scrypt error: {0}")]
    ScryptError(String),

    #[error("PBKDF2 error: {0}")]
    PBKDF2Error(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Invalid path to nodes: {0}")]
    PathToNodes(String),

    #[error("Failed to reconstruct mnemonic: {0}")]
    ReconstructMnemonicError(String),

    #[error("Mnemonic error: {0}")]
    MnemonicError(String),
}

impl KeystoreError {
    /// Converts any error that implements Display into a KeystoreError::GenericError
    pub fn from<E: fmt::Display>(error: E) -> Self {
        Self::GenericError(error.to_string())
    }
}

impl From<&str> for KeystoreError {
    fn from(err: &str) -> Self {
        Self::GenericError(err.to_string())
    }
}
