#![warn(unused_crate_dependencies)]
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(test)]
use hex_literal as _;

#[cfg(test)]
use json as _;

#[cfg(test)]
use proptest as _;

#[cfg(test)]
use rand_core as _;

#[cfg(test)]
use assert_matches as _;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    pairing::{Pairing, PairingOutput},
    AffineRepr, CurveGroup,
};
use ark_ff::{BigInteger256, Field, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::One;
use consts::{BLS_SIG_KEYGEN_SALT, BN254_CURVE_ORDER};
use errors::BLSError;
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

pub mod consts;
pub mod errors;
pub mod keystores;
pub mod mnemonics;
pub mod utils;

pub const CHINESE_SIMPLIFIED_WORD_LIST: &str = include_str!("word_lists/chinese_simplified.txt");
pub const CHINESE_TRADITIONAL_WORD_LIST: &str = include_str!("word_lists/chinese_traditional.txt");
pub const CZECH_WORD_LIST: &str = include_str!("word_lists/czech.txt");
pub const ENGLISH_WORD_LIST: &str = include_str!("word_lists/english.txt");
pub const ITALIAN_WORD_LIST: &str = include_str!("word_lists/italian.txt");
pub const KOREAN_WORD_LIST: &str = include_str!("word_lists/korean.txt");
pub const PORTUGUESE_WORD_LIST: &str = include_str!("word_lists/portuguese.txt");
pub const SPANISH_WORD_LIST: &str = include_str!("word_lists/spanish.txt");

pub fn pairing(u: G2Affine, v: G1Affine) -> PairingOutput<Bn254> {
    Bn254::pairing(v, u)
}

fn xmd_hash_function(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

fn i2osp(x: usize, x_len: usize) -> Vec<u8> {
    let mut result = vec![0u8; x_len];
    let mut x = x;
    for i in (0..x_len).rev() {
        result[i] = (x & 0xff) as u8;
        x >>= 8;
    }
    result
}

fn os2ip(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

pub fn key_gen(ikm: &[u8], key_info: &[u8]) -> BigUint {
    let curve_order = BigUint::parse_bytes(BN254_CURVE_ORDER.as_bytes(), 10).unwrap();
    let mut salt = BLS_SIG_KEYGEN_SALT.to_vec();
    let mut sk = BigUint::zero();

    while sk.is_zero() {
        salt = xmd_hash_function(&salt);
        let mut temp_idk = ikm.to_vec();
        temp_idk.extend_from_slice(&[0u8]);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &temp_idk);
        let mut okm = vec![0u8; (1.5 * ((curve_order.bits() as f64) / 8.0)).ceil() as usize];
        let mut temp_key_info = key_info.to_vec();
        temp_key_info.extend_from_slice(&i2osp(okm.len(), 2));
        hkdf.expand(&temp_key_info, &mut okm).unwrap();
        sk = os2ip(&okm) % &curve_order;
    }
    sk
}

pub fn sk_to_pk_g2(sk: &[u8]) -> Vec<u8> {
    let _sk = Fr::from_be_bytes_mod_order(sk);
    let mut compressed_bytes = Vec::new();
    let pk = G2Projective::from(G2Affine::generator()) * _sk;
    pk.serialize_uncompressed(&mut compressed_bytes).unwrap();
    compressed_bytes
}

pub fn sk_to_pk_g1(sk: &[u8]) -> Vec<u8> {
    let _sk = Fr::from_be_bytes_mod_order(sk);
    let mut compressed_bytes = Vec::new();
    let pk = G1Projective::from(G1Affine::generator()) * _sk;
    pk.serialize_uncompressed(&mut compressed_bytes).unwrap();
    compressed_bytes
}

fn hash_to_curve(digest: &[u8]) -> G1Affine {
    let one = Fq::one();
    let three = Fq::from(3u64);

    let mut hasher = Sha256::new();
    hasher.update(digest);
    let hashed_result = hasher.finalize();

    // Convert digest to a big integer and then to a field element
    let mut x = {
        let big_int = BigUint::from_bytes_be(&hashed_result);
        let mut bytes = [0u8; 32];
        big_int
            .to_bytes_be()
            .iter()
            .rev()
            .enumerate()
            .for_each(|(i, &b)| bytes[i] = b);
        Fq::from_le_bytes_mod_order(&bytes)
    };

    loop {
        // y = x^3 + 3
        let mut y = x;
        y.square_in_place();
        y *= x;
        y += three;

        // Check if y is a quadratic residue (i.e., has a square root in the field)
        if let Some(y) = y.sqrt() {
            return G1Projective::new(x, y, Fq::one()).into_affine();
        } else {
            // x = x + 1
            x += one;
        }
    }
}

pub fn sign(sk: Fr, message: &[u8]) -> Result<G1Affine, BLSError> {
    let q = hash_to_curve(message);

    let sk_int: BigInteger256 = sk.into();
    let r = q.mul_bigint(sk_int);

    if !r.into_affine().is_on_curve() || !r.into_affine().is_in_correct_subgroup_assuming_on_curve()
    {
        return Err(BLSError::SignatureNotInSubgroup);
    }

    Ok(r.into_affine())
}

pub fn verify(public_key: G2Affine, message: &[u8], signature: G1Affine) -> bool {
    if !signature.is_in_correct_subgroup_assuming_on_curve() || !signature.is_on_curve() {
        return false;
    }

    let q = hash_to_curve(message);
    let c1 = pairing(public_key, q);
    let c2 = pairing(G2Affine::generator(), signature);
    c1 == c2
}

pub fn aggregate_signatures(signatures: &[G1Affine]) -> Result<G1Affine, BLSError> {
    if signatures.is_empty() {
        return Err(BLSError::SignatureListEmpty);
    }

    let signatures_in_projective: Vec<G1Projective> = signatures
        .iter()
        .map(|sig| {
            let proj = G1Projective::from(*sig);
            if !sig.is_on_curve() || !sig.is_in_correct_subgroup_assuming_on_curve() {
                return Err(BLSError::SignatureNotInSubgroup);
            }
            Ok(proj)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut aggregated = signatures_in_projective[0];
    for sig in &signatures[1..] {
        aggregated += sig;
    }
    Ok(aggregated.into_affine())
}

pub fn aggregate_public_keys(public_keys: &[G2Affine]) -> Result<G2Affine, BLSError> {
    if public_keys.is_empty() {
        return Err(BLSError::PublicKeyListEmpty);
    }

    let public_keys_in_projective: Vec<G2Projective> = public_keys
        .iter()
        .map(|pk| {
            let proj = G2Projective::from(*pk);
            if !pk.is_on_curve() || !pk.is_in_correct_subgroup_assuming_on_curve() {
                return Err(BLSError::PublicKeyNotInSubgroup);
            }
            Ok(proj)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut aggregated = public_keys_in_projective[0];
    for pk in &public_keys_in_projective[1..] {
        aggregated += *pk;
    }

    Ok(aggregated.into_affine())
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::G2Projective;
    use ark_ec::AdditiveGroup;
    use ark_ff::UniformRand;
    use ark_std::{ops::Mul, test_rng};

    #[test]
    fn test_aggregate_and_verify() {
        let mut rng = test_rng();

        // Generate private keys and corresponding public keys
        let private_keys: Vec<Fr> = (0..500).map(|_| Fr::rand(&mut rng)).collect();
        let public_keys: Vec<G2Affine> = private_keys
            .iter()
            .map(|sk| (G2Affine::generator() * sk).into_affine())
            .collect();

        let message = b"Test message";

        // Sign the message with each private key
        let signatures: Vec<G1Affine> = private_keys
            .iter()
            .map(|sk| sign(*sk, message).unwrap())
            .collect();

        // Aggregate the signatures and public keys
        let aggregated_signature = aggregate_signatures(&signatures).unwrap();
        let aggregated_public_key = aggregate_public_keys(&public_keys).unwrap();

        // Verify the aggregated signature with the aggregated public key
        let is_valid = verify(aggregated_public_key, message, aggregated_signature);
        assert!(is_valid, "Aggregated signature verification failed");
    }

    #[test]
    fn test_generic() {
        let mut rng = ark_std::test_rng();
        let sk = Fr::rand(&mut rng);
        let pubkey = G2Projective::from(G2Affine::generator())
            .mul(sk)
            .into_affine();

        let message = "random".as_bytes();
        let message2 = "random2".as_bytes();

        let sig = sign(sk, &message.to_vec()).unwrap();

        let res = verify(pubkey, &message2.to_vec(), sig);
        print!("{}", res);
    }

    #[test]
    fn test_aggregate_signatures() {
        let mut rng = test_rng();

        // Generate valid signatures
        let signatures: Vec<G1Affine> = (0..5).map(|_| G1Affine::rand(&mut rng)).collect();

        // Aggregate the signatures
        let result = aggregate_signatures(&signatures);
        assert!(result.is_ok());

        // Test with an empty list
        let empty_signatures: Vec<G1Affine> = vec![];
        let result = aggregate_signatures(&empty_signatures);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            BLSError::SignatureListEmpty.to_string()
        );

        // Test with an invalid signature
        let mut invalid_signature = G1Affine::rand(&mut rng);
        invalid_signature.y = invalid_signature.y.double(); // This makes it invalid
        let mut invalid_signatures = signatures.clone();
        invalid_signatures.push(invalid_signature);
        let result = aggregate_signatures(&invalid_signatures);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            BLSError::SignatureNotInSubgroup.to_string()
        );
    }

    #[test]
    fn test_aggregate_public_keys() {
        let mut rng = test_rng();

        // Generate valid public keys
        let public_keys: Vec<G2Affine> = (0..5).map(|_| G2Affine::rand(&mut rng)).collect();

        // Aggregate the public keys
        let result = aggregate_public_keys(&public_keys);
        assert!(result.is_ok());

        // Test with an empty list
        let empty_public_keys: Vec<G2Affine> = vec![];
        let result = aggregate_public_keys(&empty_public_keys);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            BLSError::PublicKeyListEmpty.to_string()
        );

        // Test with an invalid public key
        let mut invalid_public_key = G2Affine::rand(&mut rng);
        invalid_public_key.y = invalid_public_key.y.double(); // This makes it invalid
        let mut invalid_public_keys = public_keys.clone();
        invalid_public_keys.push(invalid_public_key);
        let result = aggregate_public_keys(&invalid_public_keys);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            BLSError::PublicKeyNotInSubgroup.to_string()
        );
    }
}
