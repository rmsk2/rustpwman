use std::io::{Error, ErrorKind};
use std::io::Read;
use std::io::Write;
use crate::fcrypt::{Cryptor, AeadContext, KdfId, KeyDeriver, DEFAULT_TAG_SIZE};
use crate::derivers;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, AeadInPlace};


pub struct ChaCha20Poly1305Context(AeadContext);

impl ChaCha20Poly1305Context {
    #![allow(dead_code)]
    pub fn new() -> ChaCha20Poly1305Context {
        return ChaCha20Poly1305Context(AeadContext::new_with_kdf(derivers::sha256_deriver, KdfId::Sha256))
    }

    pub fn new_with_kdf(derive: KeyDeriver, deriver_id: KdfId) -> ChaCha20Poly1305Context {
        return ChaCha20Poly1305Context(AeadContext::new_with_kdf(derive, deriver_id));
    }    
}

impl Cryptor for ChaCha20Poly1305Context {
    fn decrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        if data.len() < DEFAULT_TAG_SIZE {
            return Err(Error::new(ErrorKind::Other, "Ciphertext too short"));
        }
        let associated_data: [u8; 0] = [];

        let (key, nonce, tag, mut dec_buffer) = self.0.prepare_params_decrypt(password, data);

        let cipher = ChaCha20Poly1305::new(&key);
        let _ = match cipher.decrypt_in_place_detached(&nonce, &associated_data, &mut dec_buffer[0..], &tag) {
            Ok(_) => (),
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "ChaCha20 Decryption error"));
            }
        };

        return Ok(dec_buffer);        
    }

    fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        let (key, nonce) = self.0.prepare_params_encrypt(password);
        let cipher = ChaCha20Poly1305::new(&key);

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