use std::io::Read;
use std::io::Write;
use crate::fcrypt::{Cryptor, AeadContext, KdfId, KeyDeriver};
use crate::derivers;
use cipher::generic_array::typenum;
use aes_gcm::AesGcm;

pub struct GcmContext(AeadContext);

impl GcmContext {
    #![allow(dead_code)]
    pub fn new() -> GcmContext {
        return GcmContext(AeadContext::new_with_kdf(derivers::sha256_deriver, KdfId::Sha256))
    }

    pub fn new_with_kdf(derive: KeyDeriver, deriver_id: KdfId) -> GcmContext {
        return GcmContext(AeadContext::new_with_kdf(derive, deriver_id));
    }
}

impl Cryptor for GcmContext {
    fn decrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        return self.0.decrypt_aead::<AesGcm::<aes::Aes256, typenum::U12>>(password, data, "AES256-GCM");
    }

    fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        return self.0.encrypt_aead::<AesGcm::<aes::Aes256, typenum::U12>>(password, data, "AES256-GCM");
    }

    fn from_dyn_reader(&mut self, reader: &mut dyn Read)-> std::io::Result<Vec<u8>> {
        return self.0.from_reader(reader);
    }

    fn to_dyn_writer(&self, writer: &mut dyn Write, data: &Vec<u8>) -> std::io::Result<()> {
        return self.0.to_writer(writer, data);
    }        
}
