use std::{collections::{HashMap, HashSet}, fs::File, io::{self, BufRead, BufReader}, path::Path};
use num_bigint::BigUint;
use std::ops::Shl;
use num_traits::{ToPrimitive, Zero};
use rand::Rng;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512, Digest};
use unicode_normalization::UnicodeNormalization;

use crate::{consts::SUPPORTED_LANGUAGES, errors::KeystoreError};
use super::Mnemonic;    

impl Mnemonic {
    
    pub fn get_seed(mnemonic: &str, password: &str) -> [u8; 64] {
        let encoded_mnemonic = mnemonic.nfkd().collect::<String>().into_bytes();
        let salt = format!("mnemonic{}", password.nfkd().collect::<String>()).into_bytes();
        
        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(&encoded_mnemonic, &salt, 2048, &mut seed);
        seed
    }

    fn load_word_list(language: &str, words_path: &str) -> Vec<String> {
        let file_path = format!("{}/{}.txt", words_path, language);
        let file = File::open(file_path).expect("Unable to open word list file");
        let reader = BufReader::new(file);
        reader.lines().map(|line| line.expect("Unable to read line")).collect()
    }

    pub fn get_word_list(language: &str, words_path: &str) -> io::Result<Vec<String>> {
        let path = Path::new(words_path).join(format!("{}.txt", language));
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        reader.lines().collect()
    }

    fn abbreviate_word(word: &String) -> String {
        let normalized_word = word.nfkc().collect::<String>();
        if normalized_word.len() < 4 {
            normalized_word.chars().take(normalized_word.len()).collect()
        } else {
            normalized_word.chars().take(4).collect()
        }
    }

    fn abbreviate_words(words: &[String]) -> Vec<String> {
        words.iter()
            .map(|word| {
                Self::abbreviate_word(word)
            })
            .collect()
    }

    fn determine_mnemonic_language(mnemonic: &str, words_path: &str) -> Result<Vec<String>, KeystoreError> {
        let languages = SUPPORTED_LANGUAGES;
        let mut word_language_map: HashMap<String, String> = HashMap::new();

        for lang in languages {
            let abbrev_word_list = Self::get_word_list(&lang, words_path)?;
            for word in abbrev_word_list {
                word_language_map.insert(word.clone(), lang.to_string());
            }
        }

        let mnemonic_list: Vec<String> = mnemonic.to_lowercase().split_whitespace().map(|word| word.to_string()).collect();
        let abbrev_mnemonic_list = Self::abbreviate_words(&mnemonic_list);
        let mut word_languages: HashSet<String> = HashSet::new();
        let mut found = 0;

        for (word, to_lang) in word_language_map.iter(){
            let abbrev_word_from_map = Self::abbreviate_word(word);

            for abbrev in &abbrev_mnemonic_list {
                if abbrev_word_from_map == *abbrev {
                    word_languages.insert(to_lang.clone());
                    found += 1;
                }
            }
        }

        if found < mnemonic_list.len() {
            return Err(KeystoreError::MnemonicError(format!("A Word was not found in any mnemonic word lists.")));
        }

        Ok(word_languages.into_iter().collect())
    }

    fn validate_entropy_length(entropy: &[u8]) {
        let entropy_length = entropy.len() * 8;
        let valid_lengths = [128, 160, 192, 224, 256];
        if !valid_lengths.contains(&entropy_length) {
            panic!(
                "`entropy_length` should be in [128, 160, 192, 224, 256]. Got {}.",
                entropy_length
            );
        }
    }

    pub fn get_mnemonic(language: &str, words_path: &str, entropy: Option<&[u8]>) -> Result<String, KeystoreError> {
        let entropy = match entropy {
            Some(e) => e.to_vec(),
            None => {
                let mut rng = rand::thread_rng();
                (0..32).map(|_| rng.gen()).collect()
            }
        };

        let entropy_length = entropy.len() * 8;
        let checksum_length = entropy_length / 32;
        let checksum = Self::get_checksum(&entropy);
        let mut entropy_bits = BigUint::from_bytes_be(&entropy) << checksum_length;
        entropy_bits += BigUint::from(checksum);
        let total_length = entropy_length + checksum_length;

        let word_list = Self::load_word_list(language, words_path);
        let mut mnemonic = Vec::new();

        for i in (0..(total_length) / 11).rev() {
            let index = (&entropy_bits >> (i * 11)) & BigUint::from(0x7FFu64);
            let index_u32 = u32::from_str_radix(&index.to_str_radix(16), 16).map_err(|e| KeystoreError::MnemonicError(e.to_string()))?; 
            mnemonic.push(word_list[index_u32 as usize].as_str());
        }

        Ok(mnemonic.join(" "))
    }

    fn uint11_array_to_uint(uint11_array: &[u16]) -> BigUint {
        let mut result = BigUint::zero();
        for (i, &x) in uint11_array.iter().rev().enumerate() {
            let shift = BigUint::from(x) << (i * 11);
            result += shift;
        }
        result
    }

    fn get_checksum(entropy: &[u8]) -> BigUint {
        Self::validate_entropy_length(entropy);
        let checksum_length = entropy.len() / 4;
        let hash = Sha256::digest(entropy);
        let hash_biguint = BigUint::from_bytes_be(&hash);
        let checksum = hash_biguint >> (256 - checksum_length);
        checksum
    }

    pub fn reconstruct_mnemonic(mnemonic: &str, words_path: &str) -> Result<String, KeystoreError> {
        let languages = Self::determine_mnemonic_language(mnemonic, words_path)?;
        let mut reconstructed_mnemonic: Option<String> = None;

        for language in languages {
            let word_list = Self::load_word_list(&language, words_path);
            let abbrev_word_list = Self::abbreviate_words(&word_list);
            let modified: Vec<String> = mnemonic.split_whitespace().map(|s| s.to_string()).collect();
            let abbrev_mnemonic_list: Vec<String> = Self::abbreviate_words(&modified);

            if abbrev_mnemonic_list.len() < 12 || abbrev_mnemonic_list.len() > 24 || abbrev_mnemonic_list.len() % 3 != 0 {
                return Err(KeystoreError::ReconstructMnemonicError(format!("Invalid mnemonic length: {}", abbrev_mnemonic_list.len())));
            }


            let mut word_indices: Vec<usize> = Vec::new();
            let mut word_indices_error = false;
            for abbrev_word in &abbrev_mnemonic_list {
                if let Some(i) = abbrev_word_list.iter().position(|w| w == abbrev_word) {
                    word_indices.push(i);
                } else {
                    word_indices_error = true;
                    break;
                }
            }

            if word_indices_error {
                continue;
            }
            
            let checksum_length = abbrev_mnemonic_list.len() / 3;
            let refd: Vec<u16> = word_indices.iter().map(|e| 
                e.to_u16().ok_or_else(|| 
                    KeystoreError::ReconstructMnemonicError("unable to convert to u16".into()))).collect::<Result<Vec<u16>, _>>()?;
            let mnemonic_int = Self::uint11_array_to_uint(&refd);
            let mask = BigUint::from(1u32).shl(checksum_length) - BigUint::from(1u32);
            let checksum = &mnemonic_int & &mask;
            let entropy = (mnemonic_int - &checksum) >> checksum_length;
            let entropy_byte_length = checksum_length * 4;
            let mut entropy_bytes = entropy.to_bytes_be();
            while entropy_bytes.len() < entropy_byte_length {
                entropy_bytes.insert(0, 0);
            }

            let full_word_list = Self::get_word_list(&language, words_path)?;

            if Self::get_checksum(&entropy_bytes) == checksum {
                if let Some(_) = reconstructed_mnemonic {
                    return Err(KeystoreError::ReconstructMnemonicError("Mnemonic is valid in multiple languages.".into()));
                }
                reconstructed_mnemonic = Some(word_indices.into_iter().map(|index| full_word_list[index].clone()).collect::<Vec<String>>().join(" "));
            }
        }

        reconstructed_mnemonic.ok_or_else(|| KeystoreError::ReconstructMnemonicError(format!("Failed to reconstruct mnemonic. {}", mnemonic).into()))
    }

    pub fn index_to_word(word_list: &[String], index: usize) -> Result<String, String> {
        if index >= 2048 {
            return Err(format!("`index` should be less than 2048. Got {}.", index));
        }
        Ok(word_list[index].clone())
    }

}

