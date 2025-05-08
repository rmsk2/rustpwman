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

#![allow(dead_code)]

mod rijndael;
mod chacha20;
mod derivers;

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use rand::RngCore;

use serde::{Serialize, Deserialize};
use cipher::consts::{U12, U16};
use cipher::generic_array::GenericArray;
use base64::prelude::*;
use crate::persist::SendSyncPersister;
use aead::{Aead, KeyInit, AeadInPlace, AeadCore, KeySizeUser};


const DEFAULT_TAG_SIZE: usize = 16;
const DEFAULT_NONCE_SIZE: usize = 12;
const DEFAULT_SALT_SIZE: usize = 16;
// bcrypt has an input length limitation.
// It does not seem to be clear what this limitation is though.
// One recommendation is that 50 is a safe choice for all sensible
// bcrypt implementations.
const MAX_PW_SIZE_IN_BYTES: usize = 50;  

const KDF_SCRYPT: &str = "scrypt";
const KDF_ARGON2: &str = "argon2";
const KDF_SHA256: &str = "sha256"; 
const CIP_AES256: &str = "aes256";
const CIP_AES192: &str = "aes192";
const CIP_CHACHA20: &str = "chacha20";

pub const DEFAULT_KDF_ID: KdfId = KdfId::Argon2;


// This trait describes a "thing" which knows how to en- and decrypt a byte vector and to serialize, deserialize,
// load and save the encrypted data structure.
pub trait Cryptor {
    fn encrypt(&mut self, pw: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>>;
    fn decrypt(&mut self, pw: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>>;
    fn to_dyn_writer(&self, writer: &mut dyn Write, data: &Vec<u8>) -> std::io::Result<()>;
    fn from_dyn_reader(&mut self, reader: &mut dyn Read)-> std::io::Result<Vec<u8>>;
    fn algo_name(&self) -> &'static str;

    fn to_file(&self, data: &Vec<u8>, file_name: &str) -> std::io::Result<()> {
        let file = File::create(file_name)?;
        let mut w = BufWriter::new(file);

        return self.to_dyn_writer(&mut w, data);
    }

    fn persist(&self, data: &Vec<u8>, p: &mut SendSyncPersister) -> std::io::Result<()> {
        let mut res_data: Vec<u8> = vec![];
        self.to_dyn_writer(&mut res_data, data)?;

        return p.persist(&res_data);
    }

    fn from_file(&mut self, file_name: &str) -> std::io::Result<Vec<u8>> {
        let file = File::open(file_name)?;
        let mut reader = BufReader::new(file);

        return self.from_dyn_reader(&mut reader);
    }

    fn retrieve(&mut self, p: &mut SendSyncPersister) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let data = *p.retrieve()?;

        let parsed_data = self.from_dyn_reader(&mut data.as_slice())?;

        return Ok((parsed_data, data));
    } 
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum KdfId {
    Scrypt,
    Argon2,
    Sha256
}

impl KdfId {
    pub fn to_string(self) -> String {
        return String::from(self.to_str())
    }

    pub fn to_str(self) -> &'static str {
        match self {
            KdfId::Scrypt => KDF_SCRYPT,
            KdfId::Argon2 => KDF_ARGON2,
            KdfId::Sha256 => KDF_SHA256
        }
    }

    pub fn get_known_ids() -> Vec<KdfId> {
        return vec![KdfId::Scrypt, /*KdfId::Bcrypt,*/ KdfId::Argon2, KdfId::Sha256];
    }

    pub fn from_str(name: &str) -> Option<Self> {
        return KdfId::from_string(&String::from(name));
    }

    pub fn to_named_func(self) -> (KeyDeriver, KdfId) {
        match self {
            KdfId::Scrypt => (derivers::scrypt_deriver, self),
            KdfId::Argon2 => (derivers::argon2id_deriver, self),
            KdfId::Sha256 => (derivers::sha256_deriver, self)            
        }
    }

    pub fn from_string(name: &String) -> Option<Self> {
        match &name[..] {
            KDF_SHA256 => Some(KdfId::Sha256),
            KDF_SCRYPT => Some(KdfId::Scrypt),
            KDF_ARGON2 => Some(KdfId::Argon2),
            _ => None
        }
    }
}

pub enum CipherId {
    Aes256Gcm,
    Aes192Gcm,
    ChaCha20Poly1305
}

impl CipherId {
    pub fn to_str(self) -> &'static str {
        match self {
            CipherId::Aes192Gcm => CIP_AES192,
            CipherId::Aes256Gcm => CIP_AES256,
            CipherId::ChaCha20Poly1305 => CIP_CHACHA20,
        }
    }

    pub fn from_str(name: &str) -> Option<Self> {
        return match name {
            CIP_AES192 => Some(CipherId::Aes192Gcm),
            CIP_AES256 => Some(CipherId::Aes256Gcm),
            CIP_CHACHA20 => Some(CipherId::ChaCha20Poly1305),
            _ => None
        }
    }

    pub fn get_known_ids() -> Vec<CipherId> {
        #[cfg(not(feature = "chacha20"))]
        return vec![CipherId::Aes256Gcm];
        #[cfg(feature = "chacha20")]
        return vec![CipherId::Aes192Gcm, CipherId::Aes256Gcm, CipherId::ChaCha20Poly1305];
    }        

    pub fn make(self, d: KeyDeriver, i: KdfId) -> Box<dyn Cryptor> {
        match self {
            CipherId::Aes192Gcm => return Box::new(rijndael::Gcm192Context::new_with_kdf(d, i)),
            CipherId::Aes256Gcm => return Box::new(rijndael::Gcm256Context::new_with_kdf(d, i)),
            CipherId::ChaCha20Poly1305 => return Box::new(chacha20::ChaCha20Poly1305Context::new_with_kdf(d, i))
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct CryptedJson {
    #[serde(rename(deserialize = "PbKdf"))]
    #[serde(rename(serialize = "PbKdf"))]
    pbkdf: String,    
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

pub struct AeadContext {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub kdf: KeyDeriver,
    pub kdf_id: KdfId
} 

// This struct knows how to generarate, maintain, parse, serialze and deserialize a data structure which can be used to
// implement a typical AEAD encryption scheme. It does not know how to perform the encryption itself.
impl AeadContext {
    #![allow(dead_code)]
    pub fn new() -> AeadContext {
        return AeadContext::new_with_kdf_id(derivers::sha256_deriver, KdfId::Sha256)
    }

    pub fn new_with_kdf_id(derive: KeyDeriver, deriver_id: KdfId) -> AeadContext {
        return AeadContext::new_with_kdf(derive, deriver_id);
    }

    pub fn new_with_kdf(derive: KeyDeriver, deriver_id: KdfId) -> AeadContext {
        let mut res = AeadContext {
            salt: vec![0; DEFAULT_SALT_SIZE],
            nonce: vec![0; DEFAULT_NONCE_SIZE],
            kdf: derive,
            kdf_id: deriver_id
        };

        res.fill_random();

        return res;        
    }

    pub fn from_reader<T: Read>(&mut self, reader: T) -> std::io::Result<Vec<u8>> {
        let json_struct: CryptedJson = serde_json::from_reader(reader)?;

        if json_struct.pbkdf != self.kdf_id.to_string() {
            return Err(Error::new(ErrorKind::Other, format!("Key derivation function mismatch. {} was used not {}", &json_struct.pbkdf, &self.kdf_id.to_string())));
        }

        let salt = match BASE64_STANDARD.decode(&json_struct.salt) {
            Ok(s) => s,
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "Base64 decode error"));
            }
        };

        let nonce = match BASE64_STANDARD.decode(&json_struct.nonce) {
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

        let data = match BASE64_STANDARD.decode(&json_struct.data) {
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

    pub fn to_writer<T: Write>(&self, writer: T, data: &Vec<u8>) -> std::io::Result<()> {
        let j = CryptedJson {
            pbkdf: self.kdf_id.to_string(),
            salt: BASE64_STANDARD.encode(&self.salt),
            nonce: BASE64_STANDARD.encode(&self.nonce),
            data: BASE64_STANDARD.encode(data)
        };

        serde_json::to_writer_pretty(writer, &j)?;

        return Ok(());
    }

    pub fn fill_random(&mut self) {
        // ThreadRng, provided by the thread_rng function, is a handle to a thread-local CSPRNG with periodic 
        // seeding from OsRng. Because this is local, it is typically much faster than OsRng. It should be secure, 
        // though the paranoid may prefer OsRng.        
        let mut rng = rand::rng();
        
        // ToDo: Error handling with fill_bytes()?
        let mut temp_nonce: [u8; DEFAULT_NONCE_SIZE] = [0; DEFAULT_NONCE_SIZE];
        rng.fill_bytes(&mut temp_nonce);
        let mut temp_salt: [u8; DEFAULT_SALT_SIZE] = [0; DEFAULT_SALT_SIZE];
        rng.fill_bytes(&mut temp_salt);

        self.nonce = temp_nonce.to_vec();
        self.salt = temp_salt.to_vec();
    }

    pub fn regenerate_key(&self, password: &str) -> Vec<u8> {
        return (self.kdf)(&self.salt, password);
    }

    pub fn check_min_size(&self, len: usize) -> std::io::Result<()> {
        if len < DEFAULT_TAG_SIZE {
            return Err(Error::new(ErrorKind::Other, "Ciphertext too short"));
        } else {
            return Ok(());
        }       
    }

    pub fn prepare_params_encrypt(&mut self, password: &str) -> (Vec<u8>, Vec<u8>) {
        self.fill_random();

        let raw_32_byte_key = self.regenerate_key(password);

        return (raw_32_byte_key, self.nonce.clone())
    }

    pub fn prepare_params_decrypt(&mut self, password: &str, data: &Vec<u8>) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let raw_32_byte_key = self.regenerate_key(password);

        let data_len = data.len() - DEFAULT_TAG_SIZE;
        let mut dec_buffer = Vec::new();
        for i in 0..data_len {
            dec_buffer.push(data[i]);
        }
        
        let mut tag = vec![0; DEFAULT_TAG_SIZE];
        tag.copy_from_slice(&data[data_len..data.len()]);       

        return (raw_32_byte_key, self.nonce.clone(), tag, dec_buffer);
    }
}

// The following two functions provide a generic implementation of AEAD en- and decryption on the basis of an AeadContext struct for all ciphers which 
// implement the corresponding RustCrypto traits. They are therefore helper functions in order to implement the Cryptor trait in this case.
fn encrypt_aead<T: Aead + AeadInPlace + AeadCore<NonceSize = U12, TagSize = U16> + KeyInit>(ctx: &mut AeadContext, password: &str, data: &Vec<u8>, algo_name: &str) -> std::io::Result<Vec<u8>> {
    let (key, nonce) = ctx.prepare_params_encrypt(password);
    let nonce_help = GenericArray::<u8, <T as AeadCore>::NonceSize>::from_slice(nonce.as_slice());
    let key_help = GenericArray::<u8, <T as KeySizeUser>::KeySize>::from_slice(&key[0..T::key_size()]);

    let cipher = T::new(&key_help);

    return match cipher.encrypt(nonce_help, data.as_slice()) {
        Err(_) => return Err(Error::new(ErrorKind::Other, format!("{} {}", algo_name, "Encryption error"))),
        Ok(d) => Ok(d)
    };
}

fn decrypt_aead<T: Aead + AeadInPlace + AeadCore<NonceSize = U12, TagSize = U16> + KeyInit>(ctx: &mut AeadContext, password: &str, data: &Vec<u8>, algo_name: &str) -> std::io::Result<Vec<u8>> {
    ctx.check_min_size(data.len())?;
    let associated_data: [u8; 0] = [];

    let (key, nonce, tag, mut dec_buffer) = ctx.prepare_params_decrypt(password, data);

    let nonce_help = GenericArray::<u8, <T as AeadCore>::NonceSize>::from_slice(nonce.as_slice());
    let key_help = GenericArray::<u8, <T as KeySizeUser>::KeySize>::from_slice(&key[0..T::key_size()]);
    let tag_help = GenericArray::<u8, <T as AeadCore>::TagSize>::from_slice(tag.as_slice());

    let cipher = T::new(&key_help);
    let _ = match cipher.decrypt_in_place_detached(nonce_help, &associated_data, dec_buffer.as_mut_slice(), tag_help) {
        Ok(_) => (),
        Err(_) => {
            return Err(Error::new(ErrorKind::Other, format!("{} {}", algo_name, "Decryption error")));
        }
    };

    return Ok(dec_buffer);  
}

pub fn check_password(pw: &str) -> Option<Error> {
    if pw.as_bytes().len() > MAX_PW_SIZE_IN_BYTES {
        return Some(Error::new(ErrorKind::Other, "Password too long"));
    }

    return None;
}
