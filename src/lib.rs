#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use ark_ec::{pairing::PairingOutput, AffineRepr, CurveGroup};
use errors::BLSError;
use num_bigint::BigUint;
use ark_std::One;
use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger256, Field, PrimeField};
use sha2::{Digest, Sha256};

pub mod errors;

fn pairing(u: G2Affine, v: G1Affine) -> PairingOutput<Bn254> {
    Bn254::pairing(v, u)
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
        big_int.to_bytes_be().iter().rev().enumerate().for_each(|(i, &b)| bytes[i] = b);
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

    if !r.into_affine().is_on_curve() || !r.into_affine().is_in_correct_subgroup_assuming_on_curve() {
        return Err(BLSError::SignatureNotInSubgroup);
    }

    Ok(r.into_affine())
}

pub fn verify(public_key: G2Affine, message: &[u8], signature: G1Affine) -> bool {

    if !signature.is_in_correct_subgroup_assuming_on_curve() || 
    !signature.is_on_curve() {
        return false;
    }

    let q = hash_to_curve(message);
    let c1 = pairing( public_key, q);
    let c2 = pairing( G2Affine::generator(), signature);
    c1 == c2
}


#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::G2Projective;
    use ark_std::ops::Mul;
    use ark_ff::UniformRand;

    #[test]
    fn test_generic() {
        
        let mut rng = ark_std::test_rng();
        let sk = Fr::rand(&mut rng);
        let pubkey = G2Projective::from(G2Affine::generator()).mul(sk).into_affine();

        let message = "random".as_bytes();
        let message2 = "random2".as_bytes();

        let sig = sign(sk, &message.to_vec()).unwrap();

        let res = verify(pubkey, &message2.to_vec(), sig);
        print!("{}", res);
    }
}
