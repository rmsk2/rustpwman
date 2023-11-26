use std::io::{Error, ErrorKind};
use std::io::Read;
use std::io::Write;
use crate::fcrypt::{Cryptor, AeadContext, KdfId, KeyDeriver, DEFAULT_TAG_SIZE};
use cipher::generic_array::GenericArray;
use crate::derivers;
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
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

        let raw_key = self.0.regenerate_key(password);
        let chacha20_key = GenericArray::from_slice(raw_key.as_slice());
        let associated_data: [u8; 0] = [];

        let data_len = data.len() - DEFAULT_TAG_SIZE;
        let mut dec_buffer = Vec::new();
        for i in 0..data_len {
            dec_buffer.push(data[i]);
        }
        
        let nonce = Nonce::from_slice(self.0.nonce.as_slice());
        let tag = Tag::from_slice(&data[data_len..data.len()]);

        let cipher = ChaCha20Poly1305::new(&chacha20_key);
        let _ = match cipher.decrypt_in_place_detached(&nonce, &associated_data, &mut dec_buffer[0..], &tag) {
            Ok(_) => (),
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, "ChaCha20 Decryption error"));
            }
        };

        return Ok(dec_buffer);        
    }

    fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        self.0.fill_random();

        let raw_key = self.0.regenerate_key(password);
        let chacha20_key = GenericArray::from_slice(&raw_key.as_slice());
        let cipher = ChaCha20Poly1305::new(&chacha20_key);
        let nonce = Nonce::from_slice(self.0.nonce.as_slice());

        let cipher_text = match cipher.encrypt(&nonce, data.as_ref()) {
            Ok(d) => d,
            Err(_) => return Err(Error::new(ErrorKind::Other, "ChaCha20 Encryption error")),            
        };

        return Ok(cipher_text);
    }

    fn from_dyn_reader(&mut self, reader: &mut dyn Read)-> std::io::Result<Vec<u8>> {
        return self.0.from_reader(reader);
    }

    fn to_dyn_writer(&self, writer: &mut dyn Write, data: &Vec<u8>) -> std::io::Result<()> {
        return self.0.to_writer(writer, data);
    }     
}