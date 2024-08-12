use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use pbkdf2::pbkdf2_hmac;
use scrypt::{scrypt, Params};
use sha2::{Digest, Sha256, Sha512};

use crate::errors::KeystoreError;

pub fn flip_bits_256(input: &BigUint) -> BigUint {
    let max_value = (BigUint::one() << 256) - BigUint::one();
    input ^ &max_value
}

/// The SHA256 helper function.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher
        .finalize()
        .try_into()
        .expect("Hash should be 32 bytes")
}

/// The scrypt key derivation function.
pub fn scrypt_key(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    dklen: usize,
) -> Result<Vec<u8>, KeystoreError> {
    if n * r * p < 2u32.pow(20) {
        return Err(KeystoreError::ScryptError(
            "The Scrypt parameters chosen are not secure".to_string(),
        ));
    }

    validate_scrypt_params(n, r)?;

    if n == 0 {
        return Err(KeystoreError::ScryptError("The given `n` is 0".to_string()));
    }

    let params = Params::new(n.to_f32().unwrap().log2().to_u8().unwrap(), r, p, dklen)
        .map_err(|_| KeystoreError::ScryptError("Invalid Scrypt parameters".to_string()))?;
    let mut output = vec![0u8; dklen];
    // let salt_bytes = hex::decode(salt).unwrap();
    scrypt(password, salt, &params, &mut output)
        .map_err(|_| KeystoreError::ScryptError("Scrypt key derivation failed".to_string()))?;

    Ok(output)
}

fn validate_scrypt_params(n: u32, r: u32) -> Result<(), KeystoreError> {
    let exponent = (128u32 * r) / 8u32;
    let max_n = BigUint::from(2u64).pow(exponent);
    let n_biguint = BigUint::from(n);

    if n_biguint >= max_n {
        return Err(KeystoreError::ScryptError(format!(
            "The given `n` should be less than `2**(128 * r / 8)`. Got `n={}`, r={}, 2**(128 * r / 8)={}",
            n,
            r,
            max_n
        )));
    }
    Ok(())
}

/// A variant of the pbkdf2 function which uses HMAC for PRF.
pub fn pbkdf2(
    password: &[u8],
    salt: &[u8],
    dklen: usize,
    c: u32,
    prf: &str,
) -> Result<Vec<u8>, KeystoreError> {
    if !prf.contains("sha") {
        return Err(KeystoreError::PBKDF2Error(format!(
            "String 'sha' is not in `prf`({})",
            prf
        )));
    }

    // Verify the number of rounds of SHA256-PBKDF2. SHA512 not checked as use in
    // BIP39 does not require, and therefore doesn't use, safe parameters
    // (c=2048). Ref: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
    if prf.contains("sha256") && c < 2_u32.pow(18) {
        return Err(KeystoreError::PBKDF2Error(
            "The PBKDF2 parameters chosen are not secure.".to_string(),
        ));
    }

    let mut output = vec![0u8; dklen];
    if prf.contains("sha256") {
        pbkdf2_hmac::<Sha256>(password, salt, c, &mut output);
    } else if prf.contains("sha512") {
        pbkdf2_hmac::<Sha512>(password, salt, c, &mut output);
    } else {
        return Err(KeystoreError::PBKDF2Error(format!(
            "Unsupported PRF: {}",
            prf
        )));
    }

    Ok(output)
}
