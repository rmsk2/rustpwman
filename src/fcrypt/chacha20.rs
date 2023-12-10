/* Copyright 2023 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */


use std::io::Read;
use std::io::Write;
use crate::fcrypt::{Cryptor, AeadContext, KdfId, KeyDeriver};
use super::derivers;
use chacha20poly1305::ChaCha20Poly1305;
use crate::fcrypt::{decrypt_aead, encrypt_aead};

const ALGO_CHACHA20: &str = "ChaCha20 Poly-1305";

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
        return decrypt_aead::<ChaCha20Poly1305>(&mut self.0, password, data, ALGO_CHACHA20);        
    }

    fn encrypt(&mut self, password: &str, data: &Vec<u8>) -> std::io::Result<Vec<u8>> {
        return encrypt_aead::<ChaCha20Poly1305>(&mut self.0, password, data, ALGO_CHACHA20);
    }

    fn from_dyn_reader(&mut self, reader: &mut dyn Read) -> std::io::Result<Vec<u8>> {
        return self.0.from_reader(reader);
    }

    fn to_dyn_writer(&self, writer: &mut dyn Write, data: &Vec<u8>) -> std::io::Result<()> {
        return self.0.to_writer(writer, data);
    }

    fn algo_name(&self) -> &'static str {
        return ALGO_CHACHA20;
    }
}