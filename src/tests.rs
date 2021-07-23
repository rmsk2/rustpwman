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

#[cfg(test)]
use crate::fcrypt;
#[cfg(test)]
use crate::jots;
#[cfg(test)]
use crypto::scrypt::scrypt;
#[cfg(test)]
use crypto::scrypt::ScryptParams;
#[cfg(test)]
use crate::tomlconfig;
#[cfg(test)]
use std::env;

#[test]
pub fn test_fcrypt_enc_dec() {
    let mut ctx = fcrypt::GcmContext::new();
    let data_raw: Vec<u8> = vec![0; 32];

    let cipher_text = match ctx.encrypt("this is a test", &data_raw) {
        Ok(c) => c,
        Err(_) => { panic!("Encryption failed"); }
    };

    if cipher_text.len() != (32 + 16) {
        panic!("Unexpected ciphertext length {}", cipher_text.len());
    }

    let plain_again = match ctx.decrypt("this is a test", &cipher_text) {
        Ok(c) => c,
        Err(_) => { panic!("Decryption failed"); }        
    };

    if plain_again != data_raw {
        panic!("Decryption result differs from original plaintext");
    }
}

#[test]
pub fn test_fcrypt_enc_dec_empty() {
    let mut ctx = fcrypt::GcmContext::new();
    let data_raw: Vec<u8> = Vec::new();

    let cipher_text = match ctx.encrypt("this is a test", &data_raw) {
        Ok(c) => c,
        Err(_) => { panic!("Encryption failed"); }
    };

    if cipher_text.len() != 16 {
        panic!("Unexpected ciphertext length {}", cipher_text.len());
    }

    let plain_again = match ctx.decrypt("this is a test", &cipher_text) {
        Ok(c) => c,
        Err(e) => { panic!("Decryption failed {:?}", e); }        
    };

    if plain_again != data_raw {
        panic!("Decryption result differs from original plaintext");
    }
}

#[test]
pub fn test_fcrypt_dec_failure() {
    let mut ctx = fcrypt::GcmContext::new();
    let data_raw: Vec<u8> = vec![0; 32];

    let cipher_text = match ctx.encrypt("this is a test", &data_raw) {
        Ok(c) => c,
        Err(_) => { panic!("Encryption failed"); }
    };

    let _ = match ctx.decrypt("totally different password", &cipher_text) {
        Ok(_) => { panic!("This should have failed failed"); },
        Err(_) => ()        
    };
}

#[test]
pub fn test_fcrypt_enc_dec_with_json() {
    let data_raw: Vec<u8> = vec![0; 32];
    let mut cipher_json: Vec<u8> = Vec::new();

    {
        let mut ctx = fcrypt::GcmContext::new();
    
        let cipher_text = match ctx.encrypt("this is a test", &data_raw) {
            Ok(c) => c,
            Err(_) => { panic!("Encryption failed"); }
        };
    
        if cipher_text.len() != (32 + 16) {
            panic!("Unexpected ciphertext length {}", cipher_text.len());
        }
        
        match ctx.to_writer(&mut cipher_json, &cipher_text) {
            Ok(_) => (),
            Err(e) => { panic!("Serialization failed {:?}", e); }          
        }
    }

    let mut ctx2 = fcrypt::GcmContext::new();
    let cipher_raw: Vec<u8> = match ctx2.from_reader(cipher_json.as_slice()) {
        Ok(c) => c,
        Err(_) => { panic!("Deserialization failed"); }        
    };

    let plain_again = match ctx2.decrypt("this is a test", &cipher_raw) {
        Ok(c) => c,
        Err(_) => { panic!("Decryption failed"); }        
    };

    if plain_again != data_raw {
        panic!("Decryption result differs from original plaintext");
    }
}

#[test]
pub fn test_jots_serialize_deserialize() {
    let mut serialized: Vec<u8> = Vec::new();
    let t1 = String::from("test1");
    let t2 = String::from("test2");
    let t3 = String::from("test3");    
    let d1 = String::from("data1");
    let d2 = String::from("data2");   
    let d3 = String::from("data3"); 
    
    {
        let mut j = jots::Jots::new_id(fcrypt::GcmContext::sha256_deriver, fcrypt::KdfId::Sha256);
        j.insert(&t1, &d1);
        j.insert(&t2, &d2);
        j.insert(&t3, &d3);

        if j.contents.len() != 3 {
            panic!("Unexpected number of elements {}", j.contents.len());        
        }        

        match j.to_writer(&mut serialized) {
            Ok(_) => (),
            Err(e) => { panic!("Serialization failed {:?}", e); }  
        };
    }

    let mut j2 = jots::Jots::new_id(fcrypt::GcmContext::sha256_deriver, fcrypt::KdfId::Sha256);
    match j2.from_reader(serialized.as_slice()) {
        Ok(_) => (),
        Err(e) => { panic!("Deserialization failed {:?}", e); }          
    }

    if j2.contents.len() != 3 {
        panic!("Unexpected number of elements {}", j2.contents.len());        
    }

    j2.remove(&t3);

    if j2.contents.len() != 2 {
        panic!("Unexpected number of elements {}", j2.contents.len());        
    }

    if let Some(s) = j2.get(&t1)  {
        if s != "data1" {
            panic!("Wrong data for test1");            
        }
    } else {
        panic!("Unable to read data for key test1");
    }

    if let Some(s) = j2.get(&t2)  {
        if s != "data2" {
            panic!("Wrong data for test2");            
        }
    } else {
        panic!("Unable to read data for key test2");
    }    
}

#[test]
pub fn test_jots_iter() {
    let t1 = String::from("test1");
    let t2 = String::from("test2");
    let t3 = String::from("test3");    
    let d1 = String::from("data1");
    let d2 = String::from("data2");   
    let d3 = String::from("data3"); 
    
    let mut j = jots::Jots::new_id(fcrypt::GcmContext::sha256_deriver, fcrypt::KdfId::Sha256);
    j.insert(&t1, &d1);
    j.insert(&t2, &d2);
    j.insert(&t3, &d3);

    let mut count = 0;

    for i in &j {
        println!("{}", i);
        count += 1;
    }

    for i in &j {
        println!("{}", i);
        count += 1;
    }

    assert_eq!(count, 6);
}

#[test]
pub fn test_scrypt_params() {
    let parms = ScryptParams::new(14, 8, 1);
    let mut aes_key: [u8; 64] = [0; 64];

    // Test vectors from RFC7914
    scrypt("pleaseletmein".as_bytes(), "SodiumChloride".as_bytes(), &parms, &mut aes_key);
    let mut res:Vec<u8> = Vec::new();
    aes_key.iter().for_each(|i| {res.push(*i)} );

    let test_res: Vec<u8> = vec![
        0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
        0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
        0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
        0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87
    ];

    assert_eq!(test_res, aes_key);
}

#[test]
pub fn test_argon2id_params() {
    let password: [u8; 32] = [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    ];

    let salt: [u8; 16] = [0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02];
    let secret: [u8; 8] = [0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03];
    let ad_data: [u8; 12] = [0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04];

    let mut aes_key: [u8; 32] = [0; 32];

    let ctx = argon2::Argon2::new(Some(&secret), 3, 32, 4, argon2::Version::V0x13).unwrap();
    ctx.hash_password_into(argon2::Algorithm::Argon2id, &password, &salt, &ad_data, &mut aes_key).unwrap();

    let verified: [u8; 32] = [
        0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9, 0xd0,
        0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
    ];

    assert_eq!(verified, aes_key);
}

#[test]
fn test_save_load_config() {
    let mut current_dir = env::current_dir().unwrap();
    const TEST_CONF_NAME: &str = "config_test_delete_me.toml";

    current_dir.push(TEST_CONF_NAME);
    let c = tomlconfig::RustPwManSerialize::new(15, "egal1", "egal2");

    match tomlconfig::save(&current_dir, c) {
        Some(e) => panic!("{:?}", e),
        None => ()
    };

    let res = tomlconfig::load(&current_dir);
    let res_val = match res {
        Ok(v) => v,
        Err(e) => panic!("{:?}", e)
    };

    assert_eq!(res_val.seclevel, 15);
    assert_eq!(res_val.pbkdf, String::from("egal1"));
    assert_eq!(res_val.pwgen, String::from("egal2"));
}