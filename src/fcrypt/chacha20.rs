use std::io::Read;
use std::io::Write;
use crate::fcrypt::{Cryptor, AeadContext, KdfId, KeyDeriver};
use crate::derivers;
use chacha20poly1305::ChaCha20Poly1305;
use crate::fcrypt::{decrypt_aead, encrypt_aead};


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
        return decrypt_aead::<ChaCha20Poly1305>(&mut self.0, password, data, "ChaCha20Poly1305");        
    }

    fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        return encrypt_aead::<ChaCha20Poly1305>(&mut self.0, password, data, "ChaCha20Poly1305");
    }

    fn from_dyn_reader(&mut self, reader: &mut dyn Read)-> std::io::Result<Vec<u8>> {
        return self.0.from_reader(reader);
    }

    fn to_dyn_writer(&self, writer: &mut dyn Write, data: &Vec<u8>) -> std::io::Result<()> {
        return self.0.to_writer(writer, data);
    }

    fn algo_name(&self) -> &'static str {
        return "ChaCha20 Poly-1305";
    }
}