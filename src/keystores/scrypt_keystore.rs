use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::errors::KeystoreError;

use super::base_keystore::{Keystore, KeystoreCrypto, KeystoreModule};


#[derive(Debug, Serialize, Deserialize)]
pub struct ScryptKeystore(Keystore);

impl ScryptKeystore {
    pub fn new() -> Self {
        let keystore = Keystore {
            crypto: KeystoreCrypto {
                kdf: KeystoreModule {
                    function: "scrypt".to_string(),
                    params: {
                        let mut params = HashMap::new();
                        params.insert("dklen".to_string(), serde_json::Value::from(32));
                        params.insert("n".to_string(), serde_json::Value::from(2u64.pow(18)));
                        params.insert("r".to_string(), serde_json::Value::from(8));
                        params.insert("p".to_string(), serde_json::Value::from(1));
                        params
                    },
                    message: "".to_string(),
                },
                checksum: KeystoreModule {
                    function: "sha256".to_string(),
                    params: HashMap::new(),
                    message: "".to_string(),
                },
                cipher: KeystoreModule {
                    function: "aes-128-ctr".to_string(),
                    params: HashMap::new(),
                    message: "".to_string(),
                },
            },
            description: "".to_string(),
            pubkey: "".to_string(),
            path: "".to_string(),
            uuid: "".to_string(),
            version: 4,
        };
        ScryptKeystore(keystore)
    }

    pub fn encrypt(&mut self, secret: &[u8], password: &str, path: &str, 
        kdf_salt: Option<Vec<u8>>, aes_iv: Option<Vec<u8>>) -> Result<(), KeystoreError> {
        self.0.encrypt(secret, password, path, kdf_salt, aes_iv)
    }

    pub fn decrypt(&mut self, password: &str) -> Result<Vec<u8>, KeystoreError> {
        self.0.decrypt(password)
    }

    pub fn to_keystore(self) -> Keystore {
        self.0
    }

}
