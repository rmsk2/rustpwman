/* Copyright 2026 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use crate::obfuscate::Cfb8;
use rand::Rng;
use sha2::{Sha256, Digest};


pub trait PwGetter {
    fn get(&self) -> String;
    fn set(&mut self, new_pw: &str);
}

struct PasswordStore {
    password: Vec<u8>,
    password_key: Vec<u8>,
    iv: Vec<u8>
}

pub fn make_new_pwstore(store_id: &String, new_pw: &str) -> Box<dyn PwGetter + Send>{
    return Box::new(PasswordStore::new(store_id, new_pw));
}

// Use this to perform obfuscation of the master password in memory. This is more of a hygiene feature
// than a security feature because the master password will be in plaintext in memory at least
// while it is entered during en-/decryption of the whole password file. On top of that
// anyone who can inspect the memory of a running process can create a key logger to steal the master
// password and/or is root anyway .... . Additionally the obfuscation key is in plaintext in RAM.
impl PasswordStore {
    fn new(store_id: &String, new_pw: &str) -> PasswordStore {
        let mut key = vec![0u8; 16];
        rand::rng().fill_bytes(&mut key);

        let mut res = PasswordStore { password: vec![0u8; 0], password_key: key, iv: PasswordStore::derive_iv(store_id) };
        res.set(new_pw);

        return res;
    }

    fn derive_iv(store_id: &str) -> Vec<u8>{
        let mut sha = Sha256::new();
        sha.update(store_id.as_bytes());
        return sha.finalize().into_iter().take(16).collect();
    }
}

impl PwGetter for PasswordStore {
    fn set(&mut self, new_pw: &str) {
        let mut data = new_pw.as_bytes().to_vec();
        Cfb8::new_aes_128_cfb(self.password_key.clone(), self.iv.clone()).encrypt(&mut data);
        self.password = data;
    }

    fn get(&self) -> String {
        let mut data = self.password.clone();
        Cfb8::new_aes_128_cfb(self.password_key.clone(), self.iv.clone()).decrypt(&mut data);
        return String::from_utf8(data).expect("decrypted password is not valid UTF-8");
    }
}