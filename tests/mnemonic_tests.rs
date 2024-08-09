#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, G1Affine};
    use num_bigint::BigUint;
    use rust_bls_bn254::mnemonics::{path::mnemonic_and_path_to_key, Mnemonic};
    use serde::{Deserialize, Deserializer};
    use std::{collections::HashMap, fs, panic, sync::Once};

    #[allow(dead_code)]
    #[allow(non_snake_case)]
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

    #[allow(dead_code)]
    #[allow(non_snake_case)]
    #[derive(Debug, Deserialize, Clone)]
    struct TestVectorMnemonic {
        entropy: String,
        mnemonic: String,
        seed: String,
        xprv: String,
    }

    fn deserialize_biguint<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        BigUint::parse_bytes(s.as_bytes(), 10)
            .ok_or_else(|| serde::de::Error::custom("Failed to parse BigUint"))
    }

    static INIT: Once = Once::new();
    static mut TEST_VECTORS: Option<Vec<TestVector>> = None;
    static mut TEST_VECTORS_MNEMONIC: Option<HashMap<String, Vec<TestVectorMnemonic>>> = None;

    fn setup() {
        unsafe {
            INIT.call_once(|| {
                let file1 = fs::File::open("tests/test-vectors/tree_kdf_intermediate.json")
                    .expect("Unable to open test vectors file");
                TEST_VECTORS =
                    Some(serde_json::from_reader(file1).expect("Unable to parse test vectors"));

                let file2 = fs::File::open("tests/test-vectors/mnemonic.json")
                    .expect("Unable to open test vectors file");
                TEST_VECTORS_MNEMONIC =
                    Some(serde_json::from_reader(file2).expect("Unable to parse test vectors"));
            });
        }
    }

    fn get_test_vectors() -> &'static Vec<TestVector> {
        setup();
        unsafe { TEST_VECTORS.as_ref().unwrap() }
    }

    fn get_test_vectors_mnemonic() -> &'static HashMap<String, Vec<TestVectorMnemonic>> {
        setup();
        unsafe { TEST_VECTORS_MNEMONIC.as_ref().unwrap() }
    }

    #[test]
    fn test_mnemonic_and_path_to_key() {
        let test_vectors = get_test_vectors();
        for test_vector in test_vectors {
            let mnemonic = &test_vector.mnemonic;
            let password = &test_vector.password;
            let path = &test_vector.path;
            let key = &test_vector.child_SK;
            assert_eq!(
                mnemonic_and_path_to_key(mnemonic, path, password).unwrap(),
                *key
            );
        }
    }

    #[test]
    fn test_bip39() {
        let word_lists_path = "src/word_lists";
        let test_vectors = get_test_vectors_mnemonic();

        for (language, language_test_vectors) in test_vectors {
            for test in language_test_vectors {
                let test_entropy = hex::decode(&test.entropy).unwrap();
                let test_mnemonic = &test.mnemonic;
                let test_seed = hex::decode(&test.seed).unwrap();

                assert_eq!(
                    Mnemonic::get_mnemonic(language, word_lists_path, Some(&test_entropy)).unwrap(),
                    *test_mnemonic
                );
                assert_eq!(
                    Mnemonic::get_seed(test_mnemonic, "TREZOR").to_vec(),
                    test_seed
                );
            }
        }
    }

    #[test]
    fn test_reconstruct_mnemonic() {
        let test_vectors = get_test_vectors_mnemonic();
        let word_lists_path = "src/word_lists";
        for (_, language_test_vectors) in test_vectors {
            for test in language_test_vectors {
                let mnemonic = &test.mnemonic;
                match Mnemonic::reconstruct_mnemonic(mnemonic, word_lists_path) {
                    Ok(reconstructed) => assert!(
                        !reconstructed.is_empty(),
                        "Reconstructed mnemonic should not be empty"
                    ),
                    Err(err) => panic!("Test failed with error: {}", err),
                }
            }
        }
    }

    #[test]
    fn test_get_word() {
        let language = "english";
        let word_lists_path = "src/word_lists";
        let word_list = Mnemonic::get_word_list(language, word_lists_path).unwrap();

        let test_cases = vec![(0, true), (2047, true), (2048, false)];

        for (index, valid) in test_cases {
            if valid {
                Mnemonic::index_to_word(&word_list, index).unwrap();
            } else {
                let result = panic::catch_unwind(|| {
                    Mnemonic::index_to_word(&word_list, index).unwrap();
                });
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn test_nothing() {
        use ark_std::str::FromStr;

        let g1 = G1Affine::new_unchecked(
            Fq::from_str(
                "277950648056014144722774518899051149098728246263316284984520891067822832300",
            )
            .unwrap(),
            Fq::from_str(
                "16927236637669640540790285431111034664564710839671197540688155537113438534238",
            )
            .unwrap(),
        );
    }
}
