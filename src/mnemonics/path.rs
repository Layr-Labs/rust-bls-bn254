use super::{
    tree::{derive_child_sk, derive_master_sk},
    Mnemonic,
};
use crate::errors::KeystoreError;
use num_bigint::BigUint;

/// Maps from a path string to a list of indices where each index represents the
/// corresponding level in the path.
pub fn path_to_nodes(path: &str) -> Result<Vec<u32>, KeystoreError> {
    let path = path.replace(' ', "");
    if !path.chars().all(|c| "m1234567890/".contains(c)) {
        return Err(KeystoreError::PathToNodes(format!("Invalid path {}", path)));
    }

    let mut indices: Vec<&str> = path.split('/').collect();
    if indices[0] != "m" {
        return Err(KeystoreError::PathToNodes(format!(
            "The first character of path should be `m`. Got {}.",
            indices[0]
        )));
    }
    indices.remove(0);
    let result: Result<Vec<u32>, _> = indices.iter().map(|&index| index.parse::<u32>()).collect();
    result.map_err(|_| KeystoreError::PathToNodes("Failed to parse indices".into()))
}

/// Return the SK at position `path`, derived from `mnemonic`. The password is
/// to be compliant with BIP39 mnemonics that use passwords, but is not used by
/// this CLI outside of tests.
pub fn mnemonic_and_path_to_key(
    mnemonic: &str,
    path: &str,
    password: &str,
) -> Result<BigUint, KeystoreError> {
    let seed = Mnemonic::get_seed(mnemonic, password);
    let mut sk = derive_master_sk(&seed)?;
    let nodes = path_to_nodes(path)?;
    for node in nodes {
        sk = derive_child_sk(sk, node)?;
    }
    Ok(sk)
}
