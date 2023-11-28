use std::io::{Error, ErrorKind};
use std::io::Read;
use std::io::Write;
use crate::fcrypt::{Cryptor, AeadContext, KdfId, KeyDeriver};
use crate::derivers;

use cipher::generic_array::typenum;
use cipher::KeyInit;
use aes_gcm::aead::{Aead, AeadInPlace};
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
        self.0.check_min_size(data.len())?;
        let associated_data: [u8; 0] = [];

        let (key, nonce, tag, mut dec_buffer) = self.0.prepare_params_decrypt(password, data);

        let cipher: AesGcm<aes::Aes256, typenum::U12> = AesGcm::new(&key);
        let _ = match cipher.decrypt_in_place_detached(&nonce, &associated_data, dec_buffer.as_mut_slice(), &tag) {
            Ok(_) => (),
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "AES-GCM Decryption error"));
            }
        };

        return Ok(dec_buffer);
    }

    fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        let (key, nonce) = self.0.prepare_params_encrypt(password);
        let cipher: AesGcm<aes::Aes256, typenum::U12> = AesGcm::new(&key);

        return match cipher.encrypt(&nonce, data.as_slice()) {
            Err(_) => return Err(Error::new(ErrorKind::Other, "AES-GCM Encryption error")),
            Ok(d) => Ok(d)
        };
    }

    fn from_dyn_reader(&mut self, reader: &mut dyn Read)-> std::io::Result<Vec<u8>> {
        return self.0.from_reader(reader);
    }

    fn to_dyn_writer(&self, writer: &mut dyn Write, data: &Vec<u8>) -> std::io::Result<()> {
        return self.0.to_writer(writer, data);
    }        
}
