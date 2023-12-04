use std::io::Read;
use std::io::Write;
use crate::fcrypt::{Cryptor, AeadContext, KdfId, KeyDeriver};
use crate::fcrypt::{decrypt_aead, encrypt_aead};
use crate::derivers;
use cipher::generic_array::typenum;
use aes_gcm::AesGcm;

pub struct Gcm256Context(AeadContext);
const ALGO_AES256: &str = "AES-256 GCM";
const ALGO_AES192: &str = "AES-192 GCM";

impl Gcm256Context {
    #![allow(dead_code)]
    pub fn new() -> Gcm256Context {
        return Gcm256Context(AeadContext::new_with_kdf(derivers::sha256_deriver, KdfId::Sha256))
    }

    pub fn new_with_kdf(derive: KeyDeriver, deriver_id: KdfId) -> Gcm256Context {
        return Gcm256Context(AeadContext::new_with_kdf(derive, deriver_id));
    }
}

impl Cryptor for Gcm256Context {
    fn decrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        return decrypt_aead::<AesGcm::<aes::Aes256, typenum::U12>>(&mut self.0, password, data, ALGO_AES256);
    }

    fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        return encrypt_aead::<AesGcm::<aes::Aes256, typenum::U12>>(&mut self.0, password, data, ALGO_AES256);
    }

    fn from_dyn_reader(&mut self, reader: &mut dyn Read) -> std::io::Result<Vec<u8>> {
        return self.0.from_reader(reader);
    }

    fn to_dyn_writer(&self, writer: &mut dyn Write, data: &Vec<u8>) -> std::io::Result<()> {
        return self.0.to_writer(writer, data);
    }

    fn algo_name(&self) -> &'static str {
        return ALGO_AES256;
    }
}

pub struct Gcm192Context(AeadContext);

impl Gcm192Context {
    #![allow(dead_code)]
    pub fn new() -> Gcm192Context {
        return Gcm192Context(AeadContext::new_with_kdf(derivers::sha256_deriver, KdfId::Sha256))
    }

    pub fn new_with_kdf(derive: KeyDeriver, deriver_id: KdfId) -> Gcm192Context {
        return Gcm192Context(AeadContext::new_with_kdf(derive, deriver_id));
    }
}

impl Cryptor for Gcm192Context {
    fn decrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        return decrypt_aead::<AesGcm::<aes::Aes192, typenum::U12>>(&mut self.0,password, data, ALGO_AES192);
    }

    fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        return encrypt_aead::<AesGcm::<aes::Aes192, typenum::U12>>(&mut self.0, password, data, ALGO_AES192);
    }

    fn from_dyn_reader(&mut self, reader: &mut dyn Read) -> std::io::Result<Vec<u8>> {
        return self.0.from_reader(reader);
    }

    fn to_dyn_writer(&self, writer: &mut dyn Write, data: &Vec<u8>) -> std::io::Result<()> {
        return self.0.to_writer(writer, data);
    }

    fn algo_name(&self) -> &'static str {
        return ALGO_AES192;
    }
}
