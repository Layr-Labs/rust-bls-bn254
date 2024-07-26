use crate::{consts::BN254_CURVE_ORDER, errors::KeystoreError, utils::flip_bits_256};
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::{Digest, Sha256};

/// Derives the lamport SK for a given `IKM` and `salt`.
/// Ref: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2333.md#ikm_to_lamport_sk
pub fn ikm_to_lamport_sk(ikm: &[u8], salt: &[u8]) -> Vec<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; 8160];
    hk.expand(&[], &mut okm)
        .expect("HKDF-Expand should not fail");

    let mut lamport_sk = Vec::with_capacity(256);
    for chunk in okm.chunks(32) {
        let mut array = [0u8; 32];
        array.copy_from_slice(chunk);
        lamport_sk.push(array);
    }
    lamport_sk
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher
        .finalize()
        .try_into()
        .expect("Hash should be 32 bytes")
}

/// Derives the `index`th child's lamport PK from the `parent_SK`.
/// Ref: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2333.md#parent_sk_to_lamport_pk
pub fn parent_sk_to_lamport_pk(parent_sk: &BigUint, index: u32) -> [u8; 32] {
    let salt = index.to_be_bytes();
    let ikm = parent_sk.to_bytes_be();

    let lamport_0 = ikm_to_lamport_sk(&ikm, &salt);
    let not_ikm = flip_bits_256(parent_sk).to_bytes_be();
    let lamport_1 = ikm_to_lamport_sk(&not_ikm, &salt);

    let mut lamport_sks = lamport_0;
    lamport_sks.extend(lamport_1);

    let lamport_pks: Vec<[u8; 32]> = lamport_sks.iter().map(|sk| sha256(sk)).collect();

    let concatenated_pks: Vec<u8> = lamport_pks.iter().flat_map(|pk| pk.to_vec()).collect();
    sha256(&concatenated_pks)
}

/// Hashes the IKM using HKDF and returns the answer as an int modulo r, the BLS field order.
/// Ref: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2333.md#hkdf_mod_r
pub fn hkdf_mod_r(ikm: &[u8], key_info: &[u8]) -> Result<BigUint, KeystoreError> {
    let l = 48; // Length in bytes for 256-bit numbers
    let mut salt = b"BLS-SIG-KEYGEN-SALT-".to_vec();
    let curve_order = BigUint::parse_bytes(BN254_CURVE_ORDER.as_bytes(), 10)
        .ok_or(KeystoreError::GenericError("unable to parse bytes".into()))?;
    let mut sk = BigUint::default();

    while sk.is_zero() {
        let mut hasher = Sha256::new();
        hasher.update(&salt);
        salt = hasher.finalize().to_vec();

        let hk = Hkdf::<Sha256>::new(Some(&salt), &[ikm, &[0x00]].concat());
        let mut okm = vec![0u8; l];
        hk.expand(&[key_info, &(l as u16).to_be_bytes()].concat(), &mut okm)
            .map_err(|e| KeystoreError::GenericError(e.to_string()))?;
        sk = BigUint::from_bytes_be(&okm) % &curve_order;
    }
    Ok(sk)
}

/// Given a parent SK `parent_SK`, return the child SK at the supplied `index`.
/// Ref: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2333.md#derive_child_sk
pub fn derive_child_sk(parent_sk: BigUint, index: u32) -> Result<BigUint, KeystoreError> {
    if u64::from(index) >= 2u64.pow(32) {
        return Err(KeystoreError::DeriveChildSkError(format!(
            "`index` should be greater than or equal to 0 and less than 2^32. Got index={}.",
            index
        )));
    }
    let lamport_pk = parent_sk_to_lamport_pk(&parent_sk, index);
    hkdf_mod_r(&lamport_pk, &[])
}

/// Given a seed, derive the master SK.
/// Ref: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2333.md#derive_master_sk
pub fn derive_master_sk(seed: &[u8]) -> Result<BigUint, KeystoreError> {
    if seed.len() < 32 {
        return Err(KeystoreError::DeriveMasterSkError(format!(
            "`len(seed)` should be greater than or equal to 32. Got {}.",
            seed.len()
        )));
    }
    hkdf_mod_r(seed, &[])
}
