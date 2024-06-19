use std::error::Error;
use std::fmt;

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
