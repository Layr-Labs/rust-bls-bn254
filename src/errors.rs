use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum BLSError {
    SignatureNotInSubgroup,
}

impl Error for BLSError {}

impl fmt::Display for BLSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BLSError::SignatureNotInSubgroup => write!(f, "Signature not in subgroup"),
        }
    }
}
