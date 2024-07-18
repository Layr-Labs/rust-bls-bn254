
#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::Zero;
    use rust_bls_bn254::{key_gen, mnemonics::tree::{derive_child_sk, derive_master_sk, hkdf_mod_r, ikm_to_lamport_sk, parent_sk_to_lamport_pk}, utils::flip_bits_256};
    use serde::{Deserialize, Deserializer, Serialize};
    use std::{fs, sync::Once};
    use assert_matches::assert_matches;


    #[derive(Debug, Serialize, Deserialize)]
    struct KdfTest {
        seed: String,
        #[serde(deserialize_with = "deserialize_biguint")]
        master_SK: BigUint,
        child_index: u32,
        #[serde(deserialize_with = "deserialize_biguint")]
        child_SK: BigUint,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct KdfTests {
        kdf_tests: Vec<KdfTest>,
    }

    #[derive(Debug, Deserialize)]
    struct TestVector {
        mnemonic: String,
        password: String,
        seed: String,
        #[serde(deserialize_with = "deserialize_biguint")]
        master_SK: BigUint,
        path: String,
        child_index: u64,
        lamport_0: Vec<String>,
        lamport_1: Vec<String>,
        compressed_lamport_PK: String,
        #[serde(deserialize_with = "deserialize_biguint")]
        child_SK: BigUint,
    }

    fn deserialize_biguint<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BigUint::parse_bytes(s.as_bytes(), 10).ok_or_else(|| serde::de::Error::custom("Failed to parse BigUint"))
    }

    static INIT: Once = Once::new();
    static mut TEST_VECTORS: Option<Vec<TestVector>> = None;
    static mut TEST_VECTORS_TREE_KDF: Option<KdfTests> = None;


    fn setup() {
        unsafe {
            INIT.call_once(|| {
                let file1 = fs::File::open("tests/test-vectors/tree_kdf_intermediate.json")
                    .expect("Unable to open tree_kdf_intermediate vectors file");
                TEST_VECTORS = Some(serde_json::from_reader(file1).expect("Unable to parse tree_kdf_intermediate vectors"));
                let file2 = fs::File::open("tests/test-vectors/tree_kdf.json")
                    .expect("Unable to open tree_kdf vectors file");
                TEST_VECTORS_TREE_KDF = Some(serde_json::from_reader(file2).expect("Unable to parse tree_kdf vectors"));
            });
        }
    }

    fn get_test_vectors() -> &'static Vec<TestVector> {
        setup();
        unsafe { TEST_VECTORS.as_ref().unwrap() }
    }

    fn get_test_vectors_for_tree_kdf() -> &'static KdfTests {
        setup();
        unsafe { TEST_VECTORS_TREE_KDF.as_ref().unwrap() }
    }
    
    #[test]
    fn test_hkdf_mod_r() {
        for test_vector in get_test_vectors_for_tree_kdf().kdf_tests.iter() {
            assert_eq!(key_gen(&test_vector.seed.as_bytes(), &[]), hkdf_mod_r(&test_vector.seed.as_bytes(),  &[]).unwrap());
        }
    }
    
    #[test]
    fn test_hkdf_mod_r_key_info() {
        let seed = vec![0u8; 32];
        let key_infos = vec![
            vec![0u8; 32],
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xBC, 0xDE, 0xFF],
            vec![0xFF; 16],
        ];

        for key_info in key_infos {
            let expected = key_gen(&seed, &key_info);
            let result = hkdf_mod_r(&seed, &key_info).unwrap();
            assert_eq!(expected, result);
        }
    }

    #[test]
    fn test_ikm_to_lamport_sk() {
        let test_vectors = get_test_vectors();
        for test_vector in test_vectors {
            let test_vector_lamport_0: Vec<Vec<u8>> = test_vector.lamport_0.iter()
                .map(|x| hex::decode(x).unwrap())
                .collect();
            let test_vector_lamport_1: Vec<Vec<u8>> = test_vector.lamport_1.iter()
                .map(|x| hex::decode(x).unwrap())
                .collect();
            let salt = test_vector.child_index.to_be_bytes();
            let ikm = test_vector.master_SK.to_bytes_be();
            let lamport_0 = ikm_to_lamport_sk(&ikm, &salt);
            let not_ikm = flip_bits_256(&test_vector.master_SK).to_bytes_be();
            let lamport_1 = ikm_to_lamport_sk(&not_ikm, &salt);
            assert_eq!(test_vector_lamport_0, lamport_0);
            assert_eq!(test_vector_lamport_1, lamport_1);
        }
    }

    #[test]
    fn test_parent_sk_to_lamport_pk() {
        let test_vectors = get_test_vectors();
        for test_vector in test_vectors {
            let parent_sk = &test_vector.master_SK;
            let index = test_vector.child_index;
            let lamport_pk = hex::decode(&test_vector.compressed_lamport_PK).unwrap();
            assert_eq!(lamport_pk, parent_sk_to_lamport_pk(&parent_sk, index.try_into().unwrap()));
        }
    }

    #[test]
    fn test_flip_bits_256() {
        let test_vector = get_test_vectors();
        let test_vector_int = BigUint::parse_bytes(&test_vector[0].seed[..64].as_bytes(), 16).unwrap();
        let flipped = flip_bits_256(&test_vector_int);
        assert_eq!(test_vector_int & &flipped, BigUint::zero());
    }
    
    #[test]
    fn test_derive_master_sk_valid() {
        let test_vectors = &get_test_vectors_for_tree_kdf().kdf_tests;
        for test in test_vectors.iter() {
            let seed = hex::decode(&test.seed).unwrap();
            assert_eq!(derive_master_sk(&seed).unwrap(), test.master_SK);
        }
    }

    #[test]
    fn test_derive_master_sk_invalid() {
        let invalid_seed = vec![0x12; 31];
        assert!(derive_master_sk(&invalid_seed).is_err());
    }

    #[test]
    fn test_derive_child_sk_valid() {
        let test_vectors = &get_test_vectors_for_tree_kdf().kdf_tests;
        for test in test_vectors.iter() {
            let parent_sk = &test.master_SK;
            let child_sk = &test.child_SK;
            if u64::from(test.child_index) < 2u64.pow(32) {
                let index = test.child_index;
                assert_eq!(derive_child_sk(parent_sk.clone(), index.try_into().unwrap()).unwrap(), *child_sk);
            } else {
                let index = 2u64.pow(32);
                assert_matches!(
                    std::panic::catch_unwind(|| derive_child_sk(parent_sk.clone(), index.try_into().unwrap())),
                    Err(_)
                );
            }
        }
    }
}
