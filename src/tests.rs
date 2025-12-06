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

use std;

use std::collections::HashMap;
use crate::fcrypt;
use crate::jots;
use crate::pwgen::NumDigitGenerator;
use crate::pwgen::PasswordGenerator;
use crate::undo;
use argon2::AssociatedData;
use rand::Rng;
use scrypt::scrypt;
use scrypt::Params;
use crate::tomlconfig;
use std::env;
use std::fs::remove_file;
use crate::obfuscate;
use crate::jots::CryptorGen;


pub fn test_fcrypt_enc_dec_generic(generator: CryptorGen) {
    let (d, i) = fcrypt::KdfId::Sha256.to_named_func();
    let mut ctx = generator(d, i);
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
pub fn test_fcrypt_enc_dec_aes_gcm() {
    test_fcrypt_enc_dec_generic(Box::new(make_aes_gcm_cryptor));
}

#[test]
pub fn test_fcrypt_enc_dec_chacha20() {
    test_fcrypt_enc_dec_generic(Box::new(make_chacha20_cryptor));
}


pub fn test_fcrypt_enc_dec_empty_generic(generator: CryptorGen) {
    let (d, i) = fcrypt::KdfId::Sha256.to_named_func();
    let mut ctx = generator(d, i);
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
pub fn test_fcrypt_enc_dec_empty_aes_gcm() {
    test_fcrypt_enc_dec_empty_generic(Box::new(make_aes_gcm_cryptor));
}

#[test]
pub fn test_fcrypt_enc_dec_empty_aes_192_gcm() {
    test_fcrypt_enc_dec_empty_generic(Box::new(make_aes192_gcm_cryptor));
}


#[test]
pub fn test_fcrypt_enc_dec_empty_chacha20() {
    test_fcrypt_enc_dec_empty_generic(Box::new(make_chacha20_cryptor));
}

pub fn test_fcrypt_dec_failure_generic(generator: CryptorGen) {
    let (d, i) = fcrypt::KdfId::Sha256.to_named_func();
    let mut ctx = generator(d, i);
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
pub fn test_fcrypt_dec_failure_aes_gcm() {
    test_fcrypt_dec_failure_generic(Box::new(make_aes_gcm_cryptor));
}

#[test]
pub fn test_fcrypt_dec_failure_aes_192_gcm() {
    test_fcrypt_dec_failure_generic(Box::new(make_aes192_gcm_cryptor));
}


#[test]
pub fn test_fcrypt_dec_failure_chacha20() {
    test_fcrypt_dec_failure_generic(Box::new(make_chacha20_cryptor));
}


pub fn test_fcrypt_enc_dec_with_json_generic(generator: CryptorGen) {
    let data_raw: Vec<u8> = vec![0; 32];
    let mut cipher_json: Vec<u8> = Vec::new();
    let (d, i) = fcrypt::KdfId::Sha256.to_named_func();

    {
        
        let mut ctx = generator(d, i);
    
        let cipher_text = match ctx.encrypt("this is a test", &data_raw) {
            Ok(c) => c,
            Err(_) => { panic!("Encryption failed"); }
        };
    
        if cipher_text.len() != (32 + 16) {
            panic!("Unexpected ciphertext length {}", cipher_text.len());
        }
        
        match ctx.to_dyn_writer(&mut cipher_json, &cipher_text) {
            Ok(_) => (),
            Err(e) => { panic!("Serialization failed {:?}", e); }          
        }
    }

    let mut ctx2 = generator(d, i);
    let cipher_raw: Vec<u8> = match ctx2.from_dyn_reader(&mut cipher_json.as_slice()) {
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

pub fn make_chacha20_cryptor(d: fcrypt::KeyDeriver, i: fcrypt::KdfId) -> Box<dyn fcrypt::Cryptor> {
    return fcrypt::CipherId::ChaCha20Poly1305.make(d, i);
}

pub fn make_aes_gcm_cryptor(d: fcrypt::KeyDeriver, i: fcrypt::KdfId) -> Box<dyn fcrypt::Cryptor> {
    return fcrypt::CipherId::Aes256Gcm.make(d, i);
}

pub fn make_aes192_gcm_cryptor(d: fcrypt::KeyDeriver, i: fcrypt::KdfId) -> Box<dyn fcrypt::Cryptor> {
    return fcrypt::CipherId::Aes192Gcm.make(d, i);
}

#[test]
pub fn test_fcrypt_enc_dec_with_json_aes_gcm() {
    test_fcrypt_enc_dec_with_json_generic(Box::new(make_aes_gcm_cryptor));
}

#[test]
pub fn test_fcrypt_enc_dec_with_json_aes_192_gcm() {
    test_fcrypt_enc_dec_with_json_generic(Box::new(make_aes192_gcm_cryptor));
}


#[test]
pub fn test_fcrypt_enc_dec_with_json_chacha20() {
    test_fcrypt_enc_dec_with_json_generic(Box::new(make_chacha20_cryptor));
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
    let (d, i) = fcrypt::KdfId::Sha256.to_named_func();

    {        
        let mut j = jots::Jots::new_id(d, i, Box::new(make_aes_gcm_cryptor));
        j.add(&t1, &d1);
        j.add(&t2, &d2);
        j.add(&t3, &d3);

        if j.contents.len() != 3 {
            panic!("Unexpected number of elements {}", j.contents.len());        
        }        

        match j.to_writer(&mut serialized) {
            Ok(_) => (),
            Err(e) => { panic!("Serialization failed {:?}", e); }  
        };
    }

    let mut j2 = jots::Jots::new_id(d, i, Box::new(make_aes_gcm_cryptor));
    match j2.from_reader(serialized.as_slice()) {
        Ok(_) => (),
        Err(e) => { panic!("Deserialization failed {:?}", e); }          
    }

    if j2.contents.len() != 3 {
        panic!("Unexpected number of elements {}", j2.contents.len());        
    }

    j2.delete(&t3);

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
    
    let (d, i) = fcrypt::KdfId::Sha256.to_named_func();
    let mut j = jots::Jots::new_id(d, i, Box::new(make_aes_gcm_cryptor));
    j.add(&t1, &d1);
    j.add(&t2, &d2);
    j.add(&t3, &d3);

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
pub fn test_jots_iter_empty() {    
    let (d, i) = fcrypt::KdfId::Sha256.to_named_func();
    let j = jots::Jots::new_id(d, i, Box::new(make_aes_gcm_cryptor));

    let mut count = -1;

    for i in &j {
        println!("{}", i);
        count += 1;
    }

    assert_eq!(count, -1);
}

fn vec_to_hex(buf: &Vec<u8>) -> String {
    let mut result = String::from("");
    
    for i in buf {
        result.push_str(format!("{:02x}", i).as_str());
    }
    
    return result;
}

#[test]
pub fn test_sha256_key_gen() {
    let salt: &str = "0011223344556677";
    let password: &str = "Dies ist ein Test";

    let salt_vec: Vec<u8> = salt.as_bytes().to_vec();
    let (d, _) = fcrypt::KdfId::Sha256.to_named_func();
    let key = d(&salt_vec, password);
    let res = vec_to_hex(&key);

    assert_eq!(res, "8bbb8e596fdeb564b5ded3d60af1cf790a326309ada0045cc61d07fd982876d2");
}

#[test]
pub fn test_scrypt_params() {
    let parms = Params::new(14, 8, 1).unwrap();
    let mut aes_key: [u8; 64] = [0; 64];

    // Test vectors from RFC7914
    scrypt("pleaseletmein".as_bytes(), "SodiumChloride".as_bytes(), &parms, &mut aes_key).unwrap();
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
    // test vector from draft RFC draft-irtf-cfrg-argon2-13

    let password: [u8; 32] = [
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    ];

    let salt: [u8; 16] = [0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02];
    let secret: [u8; 8] = [0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03];
    let ad_data: [u8; 12] = [0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04];
    let ad_data2 = match AssociatedData::new(ad_data.as_slice()) {
        Ok(d) => d,
        _ => panic!("Unable to set associated data")
    };


    let mut params_builder = argon2::ParamsBuilder::new();
    params_builder
    .m_cost(32)
    .t_cost(3)
    .p_cost(4)
    .data(ad_data2)
    .output_len(32);

    let mut aes_key: [u8; 32] = [0; 32];
    
    let ctx = argon2::Argon2::new_with_secret(&secret, argon2::Algorithm::Argon2id, argon2::Version::V0x13, params_builder.build().unwrap()).unwrap();
    ctx.hash_password_into(&password, &salt, &mut aes_key).unwrap();

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
    let c = tomlconfig::RustPwManSerialize::new(15, "egal1", "egal2", "egal42", "egal43", "user", "password", "server", None);

    match tomlconfig::save(&current_dir, c) {
        Some(e) => panic!("{:?}", e),
        None => ()
    };

    let mut file_was_read = false;

    let res = tomlconfig::load(&current_dir, &mut file_was_read);
    let res_val = match res {
        Ok(v) => v,
        Err(e) => panic!("{:?}", e)
    };

    assert_eq!(file_was_read, true);
    assert_eq!(res_val.seclevel, 15);
    assert_eq!(res_val.pbkdf, String::from("egal1"));
    assert_eq!(res_val.pwgen, String::from("egal2"));
    assert_eq!(res_val.clip_cmd, String::from("egal42"));
    assert_eq!(res_val.webdav_user, String::from("user"));
    assert_eq!(res_val.webdav_server, String::from("server"));

    remove_file(current_dir.as_os_str().to_str().unwrap()).unwrap();
}

#[test]
#[allow(suspicious_double_ref_op)]
fn test_undo_1() {
    let mut u = undo::UndoRepo::<&str, &str>::new();
    let mut h = HashMap::<&str, &str>::new();

    //--------------

    h.insert("schnulli", "bulli");

    let undo1 = Box::new(move |s: &mut HashMap<&str, &str>| -> bool {
        s.remove("schnulli");

        return true;
    });
    u.push(&String::from("Added schnulli"), undo1);

    //--------------

    h.insert("kulli", "wulli");

    let undo2 = Box::new(move |s: &mut HashMap<&str, &str>| -> bool {
        s.remove("kulli");

        return true;
    });    

    u.push(&String::from("Added kulli"), undo2);

    //--------------

    let undo3 = Box::new(move |s: &mut HashMap<&str, &str>| -> bool {
        s.insert("kulli", "wulli");

        return true;
    });

    h.insert("kulli", "hawulli");

    u.push(&String::from("Modified kulli"), undo3);

    //--------------

    let comments = u.get_comments();

    for i in comments.into_iter() {
        println!("{}", i);
    }

    assert_eq!(h.len(), 2);

    let mut val = h.get("kulli").unwrap().clone();
    assert_eq!(val, "hawulli");
    
    u.undo_one(&mut h);
    val = h.get("kulli").unwrap().clone();
    assert_eq!(val, "wulli");
    assert_eq!(h.len(), 2);

    u.undo_one(&mut h);
    assert_eq!(h.len(), 1);
    assert_eq!(h.contains_key("schnulli"), true);

    u.undo_one(&mut h);
    assert_eq!(h.len(), 0);
    assert_eq!(u.is_all_undone(), true);

}

#[test]
#[cfg(target_family = "unix")]
fn test_obfuscator() {
    let password = String::from("Dies ist ein Täst");
    let ob_val = obfuscate::obfuscate(&password, "USER");
    let plain_again = match obfuscate::de_obfuscate(&ob_val, "USER") {
        Some(s) => s,
        None => { panic!("Obfuscation failed") }
    };

    assert_eq!(password, plain_again);

    println!("{}", &ob_val);
}

#[test]
fn test_n_digit_gen_2() {
    let alphabet = String::from("abcdefghijklmnopqrstuvwxyz234567ABCDE");
    let mut rng = rand::rng();
    let temp_alpha: Vec<char> = alphabet.chars().collect();

    for _i in 0..100 {
        let num_bytes = rng.random_range(1..=24);
        let alpha_end = rng.random_range(2..=alphabet.len());
        let temp_alpha = Vec::from(&temp_alpha[0..alpha_end]);

        let mut generator = NumDigitGenerator::new(&temp_alpha);
        let pw = generator.gen_password(num_bytes).unwrap();

        let float_sec_level = (num_bytes as f64) * 8.0;
        let ld_alpha_len = (temp_alpha.len() as f64).log2();
        let expected_len = (float_sec_level / ld_alpha_len).ceil() as usize;

        println!("{}", &pw);
        assert_eq!(pw.len(), expected_len);
    }
}

#[test]
fn test_n_digit_hex_gen() {
    let num_bytes = 8;
    let digits = String::from("0123456789ABCDEF");
    let mut generator = NumDigitGenerator::new(&digits.chars().collect());

    for _i in 0..100 {
        let pw = generator.gen_password(num_bytes).unwrap();
        println!("{}", &pw);
        assert_eq!(2 * num_bytes, pw.len());
    }
}

#[test]
fn test_n_digit_gen() {
    let num_bytes = 4;
    // base 32
    let digits = String::from("abcdefghijklmnopqrstuvwxyz234567");
    let mut generator = NumDigitGenerator::new(&digits.chars().collect());
    let sec_level_in_digits = generator.sec_level_in_digits(num_bytes * 8);

    for _i in 0..100 {
        let pw = generator.gen_password(num_bytes).unwrap();
        println!("{}", &pw);
        assert_eq!(sec_level_in_digits, pw.len());
    }
}