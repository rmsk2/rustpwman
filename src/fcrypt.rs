/* Copyright 2021 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use rand::RngCore;

use serde::{Serialize, Deserialize};
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use cipher::generic_array::typenum;
use aes;
use base64;
use aes_gcm::{Key, Nonce, AesGcm, Tag};
use aes_gcm::aead::{Aead, AeadInPlace, NewAead};
use crypto::scrypt::scrypt;
use crypto::scrypt::ScryptParams;
use bcrypt_pbkdf::bcrypt_pbkdf;

const DEFAULT_TAG_SIZE: usize = 16;
const DEFAULT_NONCE_SIZE: usize = 12;
const DEFAULT_SALT_SIZE: usize = 16;
// bcrypt has an input length limitation.
// It does not seem to be clear what this limitation is though.
// One recommendation is that 50 is a safe choice for all sensible
// bcrypt implementations.
const MAX_PW_SIZE_IN_BYTES: usize = 50;  

#[derive(Debug)]
pub enum FcryptError {
    CiphertextTooShort,
    DecryptionError,
    EncryptionError
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

pub type KeyDeriver = fn(&Vec<u8>, &str) -> Vec<u8>;

pub struct GcmContext {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kdf: KeyDeriver
} 



impl GcmContext {
    #![allow(dead_code)]
    pub fn new() -> GcmContext {
        return GcmContext::new_with_kdf(GcmContext::sha256_deriver)
    }

    pub fn new_with_kdf(derive: KeyDeriver) -> GcmContext {
        let mut res = GcmContext {
            salt: vec![0; DEFAULT_SALT_SIZE],
            nonce: vec![0; DEFAULT_NONCE_SIZE],
            kdf: derive
        };

        res.fill_random();

        return res;        
    }

    pub fn check_password(pw: &str) -> Option<Error> {
        if pw.as_bytes().len() > MAX_PW_SIZE_IN_BYTES {
            return Some(Error::new(ErrorKind::Other, "Password too long"));
        }

        return None;
    }

    pub fn bcrypt_deriver(salt: &Vec<u8>, password: &str) -> Vec<u8> {
        let mut aes_key: [u8; 32] = [0; 32];
        bcrypt_pbkdf(password, &salt[..], 1024, &mut aes_key).unwrap();
    
        let mut res:Vec<u8> = Vec::new();
        aes_key.iter().for_each(|i| { res.push(*i) });
    
        return res;
    }

    pub fn scrypt_deriver(salt: &Vec<u8>, password: &str) -> Vec<u8> {
        // N = 32768, r = 8, p = 2
        let parms = ScryptParams::new(15, 8, 2);
        let mut aes_key: [u8; 32] = [0; 32];
    
        scrypt(password.as_bytes(), salt.as_slice(), &parms, &mut aes_key);
        let mut res:Vec<u8> = Vec::new();
        aes_key.iter().for_each(|i| { res.push(*i) });
    
        return res;
    }

    pub fn sha256_deriver(salt: &Vec<u8>, password: &str) -> Vec<u8> {
        let mut res_buffer: [u8; 32] = [0; 32];
        let mut sha_256 = Sha256::new();

        sha_256.input_str(password);
        sha_256.input(salt);
        sha_256.input_str(password);

        sha_256.result(&mut res_buffer);

        return res_buffer.to_vec();
    }

    pub fn from_reader<T: Read>(&mut self, reader: T) -> std::io::Result<Vec<u8>> {
        let json_struct: CryptedJson = serde_json::from_reader(reader)?;

        let salt = match base64::decode(&json_struct.salt) {
            Ok(s) => s,
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "Base64 decode error"));
            }
        };

        let nonce = match base64::decode(&json_struct.nonce) {
            Ok(s) => s,
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "Base64 decode error"));
            }
        };

        if nonce.len() != DEFAULT_NONCE_SIZE {
            return Err(Error::new(ErrorKind::Other, "Unsupported nonce size"));
        }       

        self.salt = salt;
        self.nonce = nonce;

        let data = match base64::decode(&json_struct.data) {
            Ok(s) => s,
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "Base64 decode error"));
            }
        };

        if data.len() < DEFAULT_TAG_SIZE {
            return Err(Error::new(ErrorKind::Other, "Ciphertext too short"));
        }
    
        return Ok(data);
    }

    pub fn from_file(&mut self, file_name: &str) -> std::io::Result<Vec<u8>> {
        let file = File::open(file_name)?;
        let reader = BufReader::new(file);

        return self.from_reader(reader);

    }

    pub fn to_writer<T: Write>(&self, writer: T, data: &Vec<u8>) -> std::io::Result<()> {
        let j = CryptedJson {
            salt: base64::encode(&self.salt),
            nonce: base64::encode(&self.nonce),
            data: base64::encode(data)
        };

        serde_json::to_writer_pretty(writer, &j)?;

        return Ok(());
    }

    pub fn to_file(&self, data: &Vec<u8>, file_name: &str) -> std::io::Result<()> {
        let file = File::create(file_name)?;
        let w = BufWriter::new(file);

        return self.to_writer(w, data);
    }

    fn fill_random(&mut self) {
        // ThreadRng, provided by the thread_rng function, is a handle to a thread-local CSPRNG with periodic 
        // seeding from OsRng. Because this is local, it is typically much faster than OsRng. It should be secure, 
        // though the paranoid may prefer OsRng.        
        let mut rng = rand::thread_rng();
        
        // ToDo: Error handling with fill_bytes()?
        let mut temp_nonce: [u8; DEFAULT_NONCE_SIZE] = [0; DEFAULT_NONCE_SIZE];
        rng.fill_bytes(&mut temp_nonce);
        let mut temp_salt: [u8; DEFAULT_SALT_SIZE] = [0; DEFAULT_SALT_SIZE];
        rng.fill_bytes(&mut temp_salt);

        self.nonce = temp_nonce.to_vec();
        self.salt = temp_salt.to_vec();
    }

    fn regenerate_key(&self, password: &str) -> Vec<u8> {
        return (self.kdf)(&self.salt, password);
    }

    pub fn decrypt(&self, password: &str, data: &Vec<u8>) -> Result<Vec<u8>, FcryptError> {
        if data.len() < DEFAULT_TAG_SIZE {
            return Err(FcryptError::CiphertextTooShort);
        }

        let aes_256_key = self.regenerate_key(password);
        let key = Key::from_slice(aes_256_key.as_slice());
        let associated_data: [u8; 0] = [];

        let data_len = data.len() - DEFAULT_TAG_SIZE;
        let mut dec_buffer = Vec::new();
        for i in 0..data_len {
            dec_buffer.push(data[i]);
        }
        
        let nonce = Nonce::from_slice(self.nonce.as_slice());
        let tag = Tag::from_slice(&data[data_len..data.len()]);

        let cipher: AesGcm<aes::Aes256, typenum::U12> = AesGcm::new(key);
        let _ = match cipher.decrypt_in_place_detached(&nonce, &associated_data, &mut dec_buffer[0..], &tag) {
            Ok(_) => (),
            Err(_) => {
                return Err(FcryptError::DecryptionError);
            }
        };

        return Ok(dec_buffer);
    }

    pub fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> Result<Vec<u8>, FcryptError> {
        self.fill_random();

        let aes_256_key = self.regenerate_key(password);
        let key = Key::from_slice(aes_256_key.as_slice());

        let nonce = Nonce::from_slice(self.nonce.as_slice());

        let cipher: AesGcm<aes::Aes256, typenum::U12> = AesGcm::new(key);

        return match cipher.encrypt(&nonce, data.as_slice()) {
            Err(_) => return Err(FcryptError::EncryptionError),
            Ok(d) => Ok(d)
        };
    }
}