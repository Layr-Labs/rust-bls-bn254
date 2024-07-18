use std::{collections::HashMap, fs, os::unix::fs::PermissionsExt};

use aes::{cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher}, Aes128};
use ctr::Ctr128BE;
use num_traits::ToPrimitive;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use std::io::Write;
use crate::{consts::UNICODE_CONTROL_CHARS, errors::KeystoreError, sk_to_pk, utils::{pbkdf2, scrypt_key}};


#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct KeystoreModule {
    pub function: String,
    #[serde(default)]
    pub params: HashMap<String, serde_json::Value>,
    pub(crate) message: String,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct KeystoreCrypto {
    pub kdf: KeystoreModule,
    pub(crate) checksum: KeystoreModule,
    pub cipher: KeystoreModule,
}

impl KeystoreCrypto {
    fn from_json(json_dict: &Map<String, Value>) -> Result<Self, KeystoreError> {
        let kdf: KeystoreModule = serde_json::from_value(json_dict["kdf"].clone()).map_err(|e| KeystoreError::from(e))?;
        let checksum: KeystoreModule = serde_json::from_value(json_dict["checksum"].clone())?;
        let cipher: KeystoreModule = serde_json::from_value(json_dict["cipher"].clone())?;
        Ok(Self {
            kdf,
            checksum,
            cipher,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct Keystore {
    pub crypto: KeystoreCrypto,
    pub(crate) description: String,
    pub(crate) pubkey: String,
    pub path: String,
    pub(crate) uuid: String,
    pub(crate) version: u32,
}

impl Keystore {

    fn get_u32(param: Option<Value>) -> Result<u32, KeystoreError> {
        param.ok_or("Missing parameter".into())
            .and_then(|v| v.as_u64().ok_or("Invalid 'n' parameter".into()))
            .and_then(|v| v.to_u32().ok_or("Cannot convert 'n' to u32".into()))
    }

    fn get_u64(param: Option<Value>) -> Result<u64, KeystoreError> {
        param.ok_or("Missing parameter".into())
            .and_then(|v| v.as_u64().ok_or("Invalid 'n' parameter".into()))
    }

    fn kdf(&self, password: &[u8], salt: &[u8], n: u32, r: u32, p: u32, c: u32, dklen: usize) -> Result<Vec<u8>, KeystoreError> {
        if self.crypto.kdf.function == "scrypt" {
            Ok(scrypt_key(password, salt, n, r, p, dklen)?)
        } else if self.crypto.kdf.function == "pbkdf2" {
            let prf = self.crypto.kdf.params.get("prf")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeystoreError::GenericError("pubkey not found or not a string".into()))?;
            Ok(pbkdf2(password, salt, dklen, c, prf)?)
        } else {
            Err(KeystoreError::GenericError(format!("unsupported function {}", self.crypto.kdf.function)))
        }
    }

    fn save(&self, file_path: &str) -> std::io::Result<()> {
        let json_data = serde_json::to_string(self).unwrap();
        let mut file = fs::File::create(file_path)?;
        file.write_all(json_data.as_bytes())?;
        if cfg!(unix) {
            let mut perms = fs::metadata(file_path)?.permissions();
            perms.set_mode(0o440);
            fs::set_permissions(file_path, perms)?;
        }
        Ok(())
    }

    pub fn from_json(json_dict: &HashMap<String, serde_json::Value>) -> Result<Self, KeystoreError> {
        let crypto = KeystoreCrypto::from_json(json_dict["crypto"].as_object().unwrap())?;
        let path = json_dict
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeystoreError::GenericError("path not found or not a string".into()))?
            .to_string();
        let uuid = json_dict
            .get("uuid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeystoreError::GenericError("path not found or not a string".into()))?
            .to_string();
        let version = Self::get_u32(json_dict.get("version").cloned())?;
        let description = json_dict
            .get("description")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeystoreError::GenericError("Description not found or not a string".into()))?
            .to_string();
        let pubkey = json_dict
            .get("pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeystoreError::GenericError("pubkey not found or not a string".into()))?
            .to_string();

            Ok(Self {
            crypto,
            description,
            pubkey,
            path,
            uuid,
            version,
        })
    }

    pub fn from_file(path: &str) -> Result<Self, KeystoreError> {
        let file_content = fs::read_to_string(path).map_err(|e| KeystoreError::from(e))?;
        let json_dict: HashMap<String, serde_json::Value> = serde_json::from_str(&file_content)?;
        Ok(Self::from_json(&json_dict)?)
    }

    pub fn process_password(password: &str) -> Vec<u8> {
        let normalized: String = password.nfkd().collect();
        let filtered: String = normalized.chars().filter(|c| !UNICODE_CONTROL_CHARS.contains(c)).collect();
        filtered.as_bytes().to_vec()
    }
    
    pub fn encrypt(&mut self, secret: &[u8], password: &str, path: &str, 
        _kdf_salt: Option<Vec<u8>>, _aes_iv: Option<Vec<u8>>) -> Result<(), KeystoreError> {

        let kdf_salt = match _kdf_salt {
            Some(salt) => hex::decode(salt)?,
            None => rand::thread_rng().gen::<[u8; 32]>().to_vec(),
        };

        let aes_iv = match _aes_iv {
            Some(iv) => hex::decode(iv)?,
            None => rand::thread_rng().gen::<[u8; 16]>().to_vec(),
        };

        self.uuid = Uuid::new_v4().to_string();

        self.crypto.kdf.params.insert("salt".to_owned(), serde_json::Value::String(hex::encode(&kdf_salt)));
        self.crypto.cipher.params.insert("iv".to_string(), serde_json::Value::String(hex::encode(&aes_iv)));

        let decryption_key: Vec<u8>; 
        if !self.crypto.kdf.params.contains_key("n") || !self.crypto.kdf.params.contains_key("r") || !self.crypto.kdf.params.contains_key("p") {
            if !self.crypto.kdf.params.contains_key("c") {
                return Err(KeystoreError::GenericError("params didn't contain parameters for either scrypt or pbkdf2".into()))
            } else {
                let c = Self::get_u32(self.crypto.kdf.params.get("c").cloned())?;
                let dklen = Self::get_u32(self.crypto.kdf.params.get("dklen").cloned())? as usize;
                decryption_key = self.kdf(&Self::process_password(password), &kdf_salt, 0, 0, 0, c, dklen)?;
            }
        } else {
            let n = Self::get_u32(self.crypto.kdf.params.get("n").cloned())?;
            let r = Self::get_u32(self.crypto.kdf.params.get("r").cloned())?;
            let p = Self::get_u32(self.crypto.kdf.params.get("p").cloned())?;
            let dklen = Self::get_u32(self.crypto.kdf.params.get("dklen").cloned())? as usize;
            decryption_key = self.kdf(&Self::process_password(password), &kdf_salt, n, r, p, 0, dklen)?;
        }
        
        let key = GenericArray::from_slice(&decryption_key[..16]);
        let nonce = GenericArray::from_slice(&aes_iv);

        let mut cipher = Ctr128BE::<Aes128>::new(key, nonce);
        let mut encrypted_secret = secret.to_vec();
        cipher.apply_keystream(&mut encrypted_secret);

        self.crypto.cipher.message = hex::encode(&encrypted_secret);

        let mut hasher = Sha256::new();
        hasher.update(&decryption_key[16..32]);
        hasher.update(&encrypted_secret);
        
        self.crypto.checksum.message = hex::encode(hasher.finalize());

        self.pubkey = hex::encode(sk_to_pk(secret));
        self.path = path.to_string();

        Ok(())
    }

    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, KeystoreError> {

        let salt = hex::decode(self.crypto.kdf.params.get("salt").and_then(|v| v.as_str())
        .ok_or_else(|| KeystoreError::GenericError("salt not found".into()))?)?;

        let decryption_key: Vec<u8>; 
        if !self.crypto.kdf.params.contains_key("n") || !self.crypto.kdf.params.contains_key("r") || 
        !self.crypto.kdf.params.contains_key("p") {
            if !self.crypto.kdf.params.contains_key("c") {
                return Err(KeystoreError::DecryptionError("params didn't contain parameters for either scrypt or pbkdf2".into()))
            } else {
                let c = Self::get_u32(self.crypto.kdf.params.get("c").cloned())?;
                let dklen = Self::get_u32(self.crypto.kdf.params.get("dklen").cloned())? as usize;
                decryption_key = self.kdf(&Self::process_password(password), &salt, 0, 0, 0, c, dklen)?;
            }
        } else {
            let n = Self::get_u32(self.crypto.kdf.params.get("n").cloned())?;
            let r = Self::get_u32(self.crypto.kdf.params.get("r").cloned())?;
            let p = Self::get_u32(self.crypto.kdf.params.get("p").cloned())?;
            let dklen = Self::get_u32(self.crypto.kdf.params.get("dklen").cloned())? as usize;
            decryption_key = self.kdf(&Self::process_password(password), &salt, n, r, p, 0, dklen)?;

        }

        let mut hasher = Sha256::new();
        hasher.update(&decryption_key[16..32]);
        hasher.update(hex::decode(&self.crypto.cipher.message)?);

        let calculated_checksum = hex::encode(hasher.finalize());
        if calculated_checksum != self.crypto.checksum.message {
            return Err(KeystoreError::DecryptionError("Checksum message error".into()));
        }

        let key = GenericArray::from_slice(&decryption_key[..16]);
        let iv_hex = self.crypto.cipher.params.get("iv").ok_or(KeystoreError::DecryptionError("IV not found in cipher params".into()))?;
        let iv = hex::decode(iv_hex.as_str().ok_or(KeystoreError::DecryptionError("IV decode error".into()))?)?;
        let nonce = GenericArray::from_slice(&iv);
        let mut cipher = Ctr128BE::<Aes128>::new(key, nonce);
        let mut decrypted_message = hex::decode(&self.crypto.cipher.message)?;
        cipher.apply_keystream(&mut decrypted_message);
        Ok(decrypted_message.to_vec())
    }
    
}
