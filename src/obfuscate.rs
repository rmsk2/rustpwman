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


use std::env;
use sha2::{Sha256, Digest};
use std::str;
use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};

pub const PREFIX: &str = "##obfuscated##:";

pub fn is_obfuscation_possible(env_name: &str) -> bool {
    match env::var(env_name) {
        Ok(_) => true,
        Err(_) => false
    }
}

#[allow(dead_code)]
pub fn is_obfuscated(val: &String) -> bool {
    val.starts_with(PREFIX)
}

type ByteTransform = fn(&mut Cfb8, u8) -> u8;

pub struct Cfb8 {
    aes: Aes128,
    cur_iv: Vec<u8>,
}

impl Cfb8 {
    pub fn new_aes_128_cfb(k: Vec<u8>, i: Vec<u8> ) -> Cfb8 {
        let iv = i.clone();
        let key = cipher::Array::try_from(k.as_slice()).unwrap();
        let a = Aes128::new(&key);

        return Cfb8 {
            aes: a,
            cur_iv: iv
        }
    }

    fn shift_left(&mut self, n: u8) {
        for i in 0..self.cur_iv.len()-1 {
            self.cur_iv[i] = self.cur_iv[i+1]
        }

        let l = self.cur_iv.len()-1;

        self.cur_iv[l] = n;
    }

    fn process(&mut self, data: &mut [u8], t: ByteTransform) {
        for i in 0..data.len() {
            data[i] = t(self, data[i]);
        }
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        return self.process(data, Cfb8::encrypt_byte);
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        return self.process(data, Cfb8::decrypt_byte);
    }

    fn process_byte(&mut self, in_byte: u8) -> u8 {
        let mut block = cipher::Array::try_from(self.cur_iv.clone().as_slice()).unwrap();
        self.aes.encrypt_block(&mut block);

        let res = in_byte ^ block[0];
        return res
    }

    fn encrypt_byte(&mut self, in_byte: u8) -> u8 {
        let res = self.process_byte(in_byte);
        self.shift_left(res);

        return res;
    }

    fn decrypt_byte(&mut self, in_byte: u8) -> u8 {
        let res = self.process_byte(in_byte);
        self.shift_left(in_byte);

        return res;
    }
}

fn do_crypt(v: &mut [u8], env_name: &str, do_enc: bool) {
    let h = match env::var(env_name) {
        Ok(t) => t,
        Err(_) => {
            panic!("Unable to read environment variable '{}'", env_name);
        }
    };

    let mut sha_256: Sha256 = Sha256::new();
    sha_256.update(h.as_bytes());
    let hash_res = sha_256.finalize();

    let k: Vec<u8> = hash_res.clone().into_iter().take(16).collect();
    let i: Vec<u8> = hash_res.clone().into_iter().skip(16).collect();

    let mut c = Cfb8::new_aes_128_cfb(k, i);

    if do_enc {
        c.encrypt(v);
    } else {
        c.decrypt(v);
    }
}

pub fn obfuscate(to_obfuscate: &String, env_name: &str) -> String {
    let mut res = String::from("");
    let mut b = to_obfuscate.clone().into_bytes();
    
    do_crypt(b.as_mut_slice(), env_name, true);

    b.into_iter().for_each(|i| res.push_str(&format!("{:02X}", i)));

    return format!("{}{}", PREFIX, res);
}

pub fn de_obfuscate(to_de_obfuscate: &String, env_name: &str) -> Option<String> {
    let mut to_decrypt: Vec<u8> = vec![];
    
    if !to_de_obfuscate.starts_with(PREFIX) {
        return Some(to_de_obfuscate.clone());
    }

    let payload = to_de_obfuscate.clone().chars().skip(PREFIX.len()).collect::<String>().to_lowercase();

    if (payload.len() % 2) != 0 {
        return None;
    }

    for i in 0..(payload.len()/2) {
        let hi_nibble = match payload.chars().nth(2*i).unwrap().to_digit(16) {
            Some(n) => n as u8,
            None => {
                return None;
            }
        };

        let lo_nibble = match payload.chars().nth(2*i+1).unwrap().to_digit(16) {
            Some(n) => n as u8,
            None => {
                return None;
            }
        };   

        to_decrypt.push(hi_nibble << 4 | lo_nibble);        
    }

    do_crypt(to_decrypt.as_mut_slice(), env_name, false);

    return match str::from_utf8(to_decrypt.as_slice()) {
        Ok(s) => Some(String::from(s)),
        Err(_) => {
            return None;
        }
    }
}