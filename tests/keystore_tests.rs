#[cfg(test)]
mod test {
    use bn254_bls_keystore::keystores::{
        base_keystore::Keystore, pbkdf2_keystore::Pbkdf2Keystore, scrypt_keystore::ScryptKeystore,
    };
    use serde_json::json;
    use std::{fs, io, path::Path, sync::Once};

    static INIT: Once = Once::new();
    static mut TEST_VECTORS: Option<Vec<Keystore>> = None;
    static TEST_VECTOR_PASSWORD: &str = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑";

    fn setup() {
        unsafe {
            INIT.call_once(|| {
                let mut temp_vector: Vec<Keystore> = vec![];
                let file1 = fs::File::open("tests/test-vectors/keystores/keystore-test-0.json")
                    .expect("Unable to open keystore vectors file");
                temp_vector.push(
                    serde_json::from_reader(file1).expect("Unable to parse keystore vectors"),
                );

                let file2 = fs::File::open("tests/test-vectors/keystores/keystore-test-1.json")
                    .expect("Unable to open keystore vectors file");
                temp_vector.push(
                    serde_json::from_reader(file2).expect("Unable to parse keystore vectors"),
                );
                TEST_VECTORS = Some(temp_vector);
            });
        }
    }

    fn get_all_file_names_in_folder(folder_path: &str) -> io::Result<Vec<String>> {
        let mut file_names = Vec::new();

        for entry in fs::read_dir(folder_path)? {
            let entry = entry?;
            let file_name = entry.file_name().into_string().unwrap_or_default();
            file_names.push(file_name);
        }

        Ok(file_names)
    }

    fn get_test_vectors() -> &'static Vec<Keystore> {
        setup();
        unsafe { TEST_VECTORS.as_ref().unwrap() }
    }

    #[test]
    fn test_json_serialization() {
        let test_vectors = get_all_file_names_in_folder("tests/test-vectors/keystores").unwrap();
        for each_file in test_vectors {
            let keystore_json_str = fs::read_to_string(Path::new(&format!(
                "{}/{}/{}/{}",
                "tests", "test-vectors", "keystores", each_file
            )))
            .unwrap();
            let expected_json: serde_json::Value =
                serde_json::from_str(&keystore_json_str).unwrap();
            let expected_json_keystore: Keystore =
                serde_json::from_str(&keystore_json_str).unwrap();
            let loaded_via_keystore_fn = Keystore::from_file(&format!(
                "{}/{}/{}/{}",
                "tests", "test-vectors", "keystores", each_file
            ))
            .unwrap();
            assert_eq!(json!(loaded_via_keystore_fn), expected_json);
            assert_eq!(loaded_via_keystore_fn, expected_json_keystore);
        }
    }

    #[test]
    fn test_encrypt_decrypt_test_vectors() {
        let test_vector_keystores = get_test_vectors();
        let binding =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let test_vector_secret: &[u8] = binding.as_slice();

        for tv in test_vector_keystores {
            let iv = tv
                .crypto
                .cipher
                .params
                .get("iv")
                .unwrap()
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec();
            let salt = tv
                .crypto
                .kdf
                .params
                .get("salt")
                .unwrap()
                .as_str()
                .unwrap()
                .as_bytes()
                .to_vec();
            let generated_keystore = if tv.crypto.kdf.function.contains("pbkdf") {
                let mut keystore = Pbkdf2Keystore::new();
                keystore
                    .encrypt(
                        test_vector_secret,
                        TEST_VECTOR_PASSWORD,
                        &tv.path,
                        Some(salt),
                        Some(iv),
                    )
                    .unwrap();
                keystore.to_keystore()
            } else {
                let mut keystore = ScryptKeystore::new();
                keystore
                    .encrypt(
                        test_vector_secret,
                        TEST_VECTOR_PASSWORD,
                        &tv.path,
                        Some(salt),
                        Some(iv),
                    )
                    .unwrap();
                keystore.to_keystore()
            };

            assert_eq!(
                generated_keystore.decrypt(TEST_VECTOR_PASSWORD).unwrap(),
                test_vector_secret
            );
        }
    }

    #[test]
    fn test_generated_keystores() -> Result<(), Box<dyn std::error::Error>> {
        let test_vector_keystores = get_test_vectors();
        let binding =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let test_vector_secret: &[u8] = binding.as_slice();

        for tv in test_vector_keystores {
            let aes_iv = tv
                .crypto
                .cipher
                .params
                .get("iv")
                .and_then(|v| Some(v.as_str().unwrap().as_bytes().to_vec()))
                .unwrap();
            let kdf_salt = tv
                .crypto
                .kdf
                .params
                .get("salt")
                .and_then(|v| Some(v.as_str().unwrap().as_bytes().to_vec()))
                .unwrap();

            let generated_keystore = if tv.crypto.kdf.function.contains("pbkdf") {
                let mut keystore = Pbkdf2Keystore::new();
                keystore
                    .encrypt(
                        test_vector_secret,
                        TEST_VECTOR_PASSWORD,
                        &tv.path,
                        Some(kdf_salt),
                        Some(aes_iv),
                    )
                    .unwrap();
                keystore.to_keystore()
            } else {
                let mut keystore = ScryptKeystore::new();
                keystore
                    .encrypt(
                        test_vector_secret,
                        TEST_VECTOR_PASSWORD,
                        &tv.path,
                        Some(kdf_salt),
                        Some(aes_iv),
                    )
                    .unwrap();
                keystore.to_keystore()
            };

            assert_eq!(generated_keystore.crypto, tv.crypto);
        }
        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_pbkdf2_random_iv() {
        let binding =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let test_vector_secret: &[u8] = binding.as_slice();

        let mut keystore = Pbkdf2Keystore::new();
        keystore
            .encrypt(test_vector_secret, TEST_VECTOR_PASSWORD, "", None, None)
            .unwrap();

        let decrypted_secret = keystore.decrypt(TEST_VECTOR_PASSWORD).unwrap();
        assert_eq!(decrypted_secret, test_vector_secret);
    }

    #[test]
    fn test_encrypt_decrypt_scrypt_random_iv() {
        let binding =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let test_vector_secret: &[u8] = binding.as_slice();

        let mut keystore = ScryptKeystore::new();
        keystore
            .encrypt(test_vector_secret, TEST_VECTOR_PASSWORD, "", None, None)
            .unwrap();

        let decrypted_secret = keystore.decrypt(TEST_VECTOR_PASSWORD).unwrap();
        assert_eq!(decrypted_secret, test_vector_secret);
    }

    #[test]
    fn test_encrypt_decrypt_incorrect_password() {
        let binding =
            hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
                .unwrap();
        let test_vector_secret: &[u8] = binding.as_slice();
        let incorrect_password = [TEST_VECTOR_PASSWORD.as_bytes(), "incorrect".as_bytes()].concat();

        let mut keystore = ScryptKeystore::new();
        keystore
            .encrypt(test_vector_secret, TEST_VECTOR_PASSWORD, "", None, None)
            .unwrap();

        let decrypted_secret =
            keystore.decrypt(String::from_utf8(incorrect_password).unwrap().as_str());
        assert!(decrypted_secret.is_err());
    }

    #[test]
    fn test_process_password() {
        let test_cases = vec![
            ("\x07", b"" as &[u8]), // \a
            ("\x08", b""),          // \b
            ("\t", b""),            // \t
            ("a", b"a"),
            ("abc", b"abc"),
            ("a\x08c", b"ac"), // a\bc
        ];

        for (password, processed_password) in test_cases {
            assert_eq!(Keystore::process_password(password), processed_password);
        }
    }
}
