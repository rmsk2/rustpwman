use std::env;
use sha2::{Sha256, Digest};
use cipher::generic_array::GenericArray;
use std::str;
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use cfb8;

pub const PREFIX: &str = "##obfuscated##:";

type Aes128Cfb8Enc = cfb8::Encryptor<aes::Aes128>;
type Aes128Cfb8Dec = cfb8::Decryptor<aes::Aes128>;

pub fn is_obfuscation_possible(env_name: &str) -> bool {
    match env::var(env_name) {
        Ok(_) => true,
        Err(_) => false
    }
}

pub fn is_obfuscated(val: &String) -> bool {
    val.starts_with(PREFIX)
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
    let key = GenericArray::from_slice(k.as_slice());

    let i: Vec<u8> = hash_res.clone().into_iter().skip(16).collect();
    let iv = GenericArray::from_slice(i.as_slice());
    
    if do_enc {
        Aes128Cfb8Enc::new(&key, &iv).encrypt(v);
    } else {
        Aes128Cfb8Dec::new(&key, &iv).decrypt(v);
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