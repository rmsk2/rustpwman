/* Copyright 2021 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */


use sha2::{Sha256, Digest};
use scrypt::scrypt;
use argon2;


pub fn argon2id_deriver(salt: &Vec<u8>, password: &str) -> Vec<u8> {
    let mut aes_key: [u8; 32] = [0; 32];
    //let no_ad: [u8; 0] = [];

    let params = argon2::Params::new(15*1024, 2, 1, Some(32)).unwrap();
    // 15 MiB, t=2, p=1
    let ctx = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    ctx.hash_password_into(password.as_bytes(), &salt, &mut aes_key).unwrap();
    let mut res:Vec<u8> = Vec::new();
    aes_key.iter().for_each(|i| { res.push(*i) });

    return res;        
}

pub fn scrypt_deriver(salt: &Vec<u8>, password: &str) -> Vec<u8> {
    // N = 32768 = 2^15, r=8, p=2
    let parms = scrypt::Params::new(15, 8, 2, 32).unwrap();
    let mut aes_key: [u8; 32] = [0; 32];

    scrypt(password.as_bytes(), salt.as_slice(), &parms, &mut aes_key).unwrap();
    let mut res:Vec<u8> = Vec::new();
    aes_key.iter().for_each(|i| { res.push(*i) });

    return res;
}

pub fn sha256_deriver(salt: &Vec<u8>, password: &str) -> Vec<u8> {
    let mut sha_256: Sha256 = Sha256::new();

    sha_256.update(password);
    sha_256.update(salt);
    sha_256.update(password);
    let hash_res = sha_256.finalize();

    return hash_res.to_vec();
}