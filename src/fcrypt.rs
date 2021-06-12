use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Write;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use rand::Rng;

use serde::{Serialize, Deserialize};
use crypto::sha2::Sha256;
use crypto::digest::Digest;
use cipher::generic_array::typenum;
use aes;
use base64;
use aes_gcm::{Key, Nonce, AesGcm, Tag};
use aes_gcm::aead::{Aead, AeadInPlace, NewAead};

const DEFAULT_TAG_SIZE: usize = 16;
const DEFAULT_NONCE_SIZE: usize = 12;
const DEFAULT_SALT_SIZE: usize = 10;

#[derive(Debug)]
pub enum FcryptError {
    //UnsupportedNonceSize,
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

pub struct GcmContext {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
} 

impl GcmContext {
    pub fn new() -> GcmContext {
        let mut res = GcmContext {
            salt: vec![0; DEFAULT_SALT_SIZE],
            nonce: vec![0; DEFAULT_NONCE_SIZE]
        };

        res.fill_random();

        return res;
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

        if salt.len() != DEFAULT_SALT_SIZE {
            return Err(Error::new(ErrorKind::Other, "Unsupported salt size"));
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
        self.nonce.clear();
        self.salt.clear();

        for _ in 0..DEFAULT_SALT_SIZE {
            self.salt.push(rng.gen_range(0..256) as u8);
        }

        for _ in 0..DEFAULT_NONCE_SIZE {
            self.nonce.push(rng.gen_range(0..256) as u8);
        } 
    }

    fn regenerate_key(&self, password: &str) -> Vec<u8> {
        let mut res_buffer: [u8; 32] = [0; 32];
        let mut sha_256 = Sha256::new();

        sha_256.input_str(password);
        sha_256.input(&self.salt);
        sha_256.input_str(password);

        sha_256.result(&mut res_buffer);

        return res_buffer.to_vec();
    }

    pub fn decrypt(&self, password: &str, data: &Vec<u8>) -> Result<Vec<u8>, FcryptError> {
        if data.len() <= DEFAULT_TAG_SIZE {
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