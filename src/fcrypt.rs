use std::fs::File;
use std::io::BufReader;
use std::io::{Error, ErrorKind};

use serde::{Serialize, Deserialize};
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use cipher::generic_array::typenum;
use aes;
use base64;
use aes_gcm::{Key, Nonce, AesGcm, Tag};
use aes_gcm::aead::{AeadInPlace, NewAead};

const DEFAULT_TAG_SIZE: usize = 16;
const DEFAULT_NONCE_SIZE: usize = 12;

#[derive(Debug)]
pub enum FcryptError {
    UnsupportedNonceSize,
    CiphertextTooShort,
    DecryptionError
} 

#[derive(Serialize, Deserialize, Debug)]
struct CryptedJson {
    #[serde(rename(deserialize = "Salt"))]
    #[serde(rename(serialize = "Salt"))]
    salt: String,
    #[serde(rename(deserialize = "Nonce"))]
    #[serde(rename(serialize = "Nonce"))]
    nonce: String,
    #[serde(rename(deserialize = "Data"))]
    #[serde(rename(serialize = "Data"))]
    data: String
}

pub struct CryptedData {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub data: Vec<u8>
} 

impl CryptedData {
    pub fn from_file(file_name: &str) -> std::io::Result<CryptedData> {
        let file = File::open(file_name)?;
        let reader = BufReader::new(file);
        let json_struct: CryptedJson = serde_json::from_reader(reader)?;

        let crypted = CryptedData {
            salt: match base64::decode(&json_struct.salt) {
                Ok(s) => s,
                Err(_) => {
                    return Err(Error::new(ErrorKind::Other, "Base64 decode error"));
                }
            },
            nonce: match base64::decode(&json_struct.nonce) {
                Ok(s) => s,
                Err(_) => {
                    return Err(Error::new(ErrorKind::Other, "Base64 decode error"));
                }
            },
            data: match base64::decode(&json_struct.data) {
                Ok(s) => s,
                Err(_) => {
                    return Err(Error::new(ErrorKind::Other, "Base64 decode error"));
                }
            },            
        };

        return Ok(crypted);
    }

    pub fn regenerate_key(&self, password: &str) -> Vec<u8> {
        let mut res_buffer: [u8; 32] = [0; 32];
        let mut sha_256 = Sha256::new();

        sha_256.input_str(password);
        sha_256.input(&self.salt);
        sha_256.input_str(password);

        sha_256.result(&mut res_buffer);

        return res_buffer.to_vec();
    }

    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, FcryptError> {
        if self.nonce.len() != DEFAULT_NONCE_SIZE {
            return Err(FcryptError::UnsupportedNonceSize);
        }

        if self.data.len() <= DEFAULT_TAG_SIZE {
            return Err(FcryptError::CiphertextTooShort);
        }

        let aes_256_key = self.regenerate_key(password);
        let key = Key::from_slice(aes_256_key.as_slice());
        let associated_data: [u8; 0] = [];

        let data_len = self.data.len() - DEFAULT_TAG_SIZE;
        let mut dec_buffer = Vec::new();
        for i in 0..data_len {
            dec_buffer.push(self.data[i]);
        }
        
        let nonce = Nonce::from_slice(&self.nonce[0..DEFAULT_NONCE_SIZE]);
        let tag = Tag::from_slice(&self.data[data_len..self.data.len()]);

        let cipher: AesGcm<aes::Aes256, typenum::U12> = AesGcm::new(key);
        let _ = match cipher.decrypt_in_place_detached(&nonce, &associated_data, &mut dec_buffer[0..], &tag) {
            Ok(_) => (),
            Err(_) => {
                return Err(FcryptError::DecryptionError);
            }
        };

        return Ok(dec_buffer);
    }
}