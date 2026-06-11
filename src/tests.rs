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
use rand::RngExt;
#[cfg(feature = "withscrypt")]
use scrypt::scrypt;
#[cfg(feature = "withscrypt")]
use scrypt::Params;
use crate::tomlconfig;
use std::env;
use std::fs::remove_file;
use crate::obfuscate;
use crate::jots::CryptorGen;
use crate::fcrypt::totpcalc::{TotpParams, TotpAlgoId};
use crate::modtui::template::parse_entry;
use crate::modtui::TEMPLATE_SEP;

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
        Err(e) => { panic!("Decryption failed {}", e); }
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
            Err(e) => { panic!("Serialization failed {}", e); }
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
        let mut j = jots::Jots::new(d, i, Box::new(make_aes_gcm_cryptor));
        j.add(&t1, &d1);
        j.add(&t2, &d2);
        j.add(&t3, &d3);

        if j.len() != 3 {
            panic!("Unexpected number of elements {}", j.len());
        }        

        match j.to_writer(&mut serialized) {
            Ok(_) => (),
            Err(e) => { panic!("Serialization failed {}", e); }
        };
    }

    let mut j2 = jots::Jots::new(d, i, Box::new(make_aes_gcm_cryptor));
    match j2.from_reader(serialized.as_slice()) {
        Ok(_) => (),
        Err(e) => { panic!("Deserialization failed {}", e); }
    }

    if j2.len() != 3 {
        panic!("Unexpected number of elements {}", j2.len());
    }

    j2.delete(&t3);

    if j2.len() != 2 {
        panic!("Unexpected number of elements {}", j2.len());
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
pub fn test_jots_search() {
    let t1 = String::from("test1");
    let t2 = String::from("test2");
    let t3 = String::from("test3");
    let d1 = String::from("data1");
    let d2 = String::from("data2");
    let d3 = String::from("data3");

    let (d, i) = fcrypt::KdfId::Sha256.to_named_func();
    let mut j = jots::Jots::new(d, i, Box::new(make_aes_gcm_cryptor));
    j.add(&t1, &d1);
    j.add(&t2, &d2);
    j.add(&t3, &d3);

    let term1 = String::from("3");
    let res1 = j.search(&term1);

    assert_eq!(res1.len(), 1);
    assert_eq!(res1[0], "test3");

    let term2 = String::from("test");
    let res2 = j.search(&term2);

    assert_eq!(res2.len(), 3);

    let term3 = String::from("egal");
    let res3 = j.search(&term3);

    assert_eq!(res3.len(), 0);

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
    let mut j = jots::Jots::new(d, i, Box::new(make_aes_gcm_cryptor));
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
    let j = jots::Jots::new(d, i, Box::new(make_aes_gcm_cryptor));

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

#[cfg(feature = "withscrypt")]
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
    let c = tomlconfig::RustPwManSerialize::new(15, "egal1", "egal2", "egal42", "egal43", "user", "password", "server", None, None, None, None);

    match tomlconfig::save(&current_dir, c) {
        Some(e) => panic!("{}", e),
        None => ()
    };

    let mut file_was_read = false;

    let res = tomlconfig::load(&current_dir, &mut file_was_read);
    let res_val = match res {
        Ok(v) => v,
        Err(e) => panic!("{}", e)
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
    let sec_level_in_digits = generator.sec_level_in_chars(num_bytes * 8);

    for _i in 0..100 {
        let pw = generator.gen_password(num_bytes).unwrap();
        println!("{}", &pw);
        assert_eq!(sec_level_in_digits, pw.len());
    }
}

#[test]
fn test_totp_rfc6238_sha1() {
    let mut p = TotpParams::new();
    p.algo = TotpAlgoId::Sha1;
    p.secret = b"12345678901234567890".to_vec();
    p.digits = 8;

    assert_eq!(p.get_current_code(59),          "94287082");
    assert_eq!(p.get_current_code(1111111109),  "07081804");
    assert_eq!(p.get_current_code(1111111111),  "14050471");
    assert_eq!(p.get_current_code(1234567890),  "89005924");
    assert_eq!(p.get_current_code(2000000000),  "69279037");
    assert_eq!(p.get_current_code(20000000000), "65353130");
}

#[test]
fn test_totp_rfc6238_sha256() {
    let mut p = TotpParams::new();
    p.algo = TotpAlgoId::Sha256;
    p.secret = b"12345678901234567890123456789012".to_vec();
    p.digits = 8;

    assert_eq!(p.get_current_code(59),          "46119246");
    assert_eq!(p.get_current_code(1111111109),  "68084774");
    assert_eq!(p.get_current_code(1111111111),  "67062674");
    assert_eq!(p.get_current_code(1234567890),  "91819424");
    assert_eq!(p.get_current_code(2000000000),  "90698825");
    assert_eq!(p.get_current_code(20000000000), "77737706");
}

#[test]
fn test_totp_rfc6238_sha512() {
    let mut p = TotpParams::new();
    p.algo = TotpAlgoId::Sha512;
    p.secret = b"1234567890123456789012345678901234567890123456789012345678901234".to_vec();
    p.digits = 8;

    assert_eq!(p.get_current_code(59),          "90693936");
    assert_eq!(p.get_current_code(1111111109),  "25091201");
    assert_eq!(p.get_current_code(1111111111),  "99943326");
    assert_eq!(p.get_current_code(1234567890),  "93441116");
    assert_eq!(p.get_current_code(2000000000),  "38618901");
    assert_eq!(p.get_current_code(20000000000), "47863826");
}

// 16-char Base32 string = 80 bits = 10 bytes, no padding needed
const TOTP_TEST_SECRET: &str = "JBSWY3DPEHPK3PXP";

#[test]
fn test_parse_totp_valid_full() {
    let url = format!("otpauth://totp/Example?secret={}&algorithm=SHA1&digits=6&period=30", TOTP_TEST_SECRET);
    let p = TotpParams::from_totp_params(url).unwrap();
    assert!(matches!(p.algo, TotpAlgoId::Sha1));
    assert_eq!(p.digits, 6);
    assert_eq!(p.period, 30);
    assert!(!p.secret.is_empty());
}

#[test]
fn test_parse_totp_empty() {
    let url = String::from("");
    let p = TotpParams::from_totp_params(url);
    assert!(p.is_none());
}


#[test]
fn test_parse_totp_secret_only() {
    let url = format!("otpauth://totp/Example?secret={}", TOTP_TEST_SECRET);
    let p = TotpParams::from_totp_params(url).unwrap();
    assert!(matches!(p.algo, TotpAlgoId::Sha1));
    assert_eq!(p.digits, 6);
    assert_eq!(p.period, 30);
}

#[test]
fn test_parse_totp_url_embedded_in_text() {
    let entry = format!("Some notes\notpauth://totp/Example?secret={}\nMore text", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(entry).is_some());
}

#[test]
fn test_parse_totp_sha256() {
    let url = format!("otpauth://totp/Example?secret={}&algorithm=SHA256", TOTP_TEST_SECRET);
    let p = TotpParams::from_totp_params(url).unwrap();
    assert!(matches!(p.algo, TotpAlgoId::Sha256));
}

#[test]
fn test_parse_totp_sha512() {
    let url = format!("otpauth://totp/Example?secret={}&algorithm=SHA512", TOTP_TEST_SECRET);
    let p = TotpParams::from_totp_params(url).unwrap();
    assert!(matches!(p.algo, TotpAlgoId::Sha512));
}

#[test]
fn test_parse_totp_digits_7() {
    let url = format!("otpauth://totp/Example?secret={}&digits=7", TOTP_TEST_SECRET);
    let p = TotpParams::from_totp_params(url).unwrap();
    assert_eq!(p.digits, 7);
}

#[test]
fn test_parse_totp_digits_8() {
    let url = format!("otpauth://totp/Example?secret={}&digits=8", TOTP_TEST_SECRET);
    let p = TotpParams::from_totp_params(url).unwrap();
    assert_eq!(p.digits, 8);
}

#[test]
fn test_parse_totp_period_60() {
    let url = format!("otpauth://totp/Example?secret={}&period=60", TOTP_TEST_SECRET);
    let p = TotpParams::from_totp_params(url).unwrap();
    assert_eq!(p.period, 60);
}

#[test]
fn test_parse_totp_no_url() {
    assert!(TotpParams::from_totp_params("just some text".to_string()).is_none());
}

#[test]
fn test_parse_empty_element() {
    assert!(TotpParams::from_totp_params("otpauth://totp/Example?secret=&period=60".to_string()).is_none());
}

#[test]
fn test_parse_no_params() {
    assert!(TotpParams::from_totp_params("otpauth://totp/".to_string()).is_none());
}

#[test]
fn test_parse_double() {
    assert!(TotpParams::from_totp_params("otpauth://totp/wurscht?secret=AAAAAAAAAAAAAAAA\notpauth://totp/wurscht?secret=AAAAAAAAAAAAAAAA".to_string()).is_none());
}

#[test]
fn test_parse_totp_hotp_rejected() {
    let url = format!("otpauth://hotp/Example?secret={}", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(url).is_none());
}

#[test]
fn test_parse_totp_no_query_string() {
    assert!(TotpParams::from_totp_params("otpauth://totp/Example".to_string()).is_none());
}

#[test]
fn test_parse_totp_missing_secret() {
    assert!(TotpParams::from_totp_params("otpauth://totp/Example?digits=6&period=30".to_string()).is_none());
}

#[test]
fn test_parse_totp_invalid_base32() {
    assert!(TotpParams::from_totp_params("otpauth://totp/Example?secret=NOT!VALID!!!".to_string()).is_none());
}

#[test]
fn test_parse_totp_invalid_algorithm() {
    let url = format!("otpauth://totp/Example?secret={}&algorithm=MD5", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(url).is_none());
}

#[test]
fn test_parse_totp_digits_too_small() {
    let url = format!("otpauth://totp/Example?secret={}&digits=5", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(url).is_none());
}

#[test]
fn test_parse_totp_digits_too_large() {
    let url = format!("otpauth://totp/Example?secret={}&digits=9", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(url).is_none());
}

#[test]
fn test_parse_totp_period_zero() {
    let url = format!("otpauth://totp/Example?secret={}&period=0", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(url).is_none());
}

#[test]
fn test_parse_totp_period_too_large() {
    let url = format!("otpauth://totp/Example?secret={}&period=61", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(url).is_none());
}

#[test]
fn test_parse_totp_period_not_numeric() {
    let url = format!("otpauth://totp/Example?secret={}&period=XYZ", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(url).is_none());
}

#[test]
fn test_parse_totp_digits_not_numeric() {
    let url = format!("otpauth://totp/Example?secret={}&digits=XYZ", TOTP_TEST_SECRET);
    assert!(TotpParams::from_totp_params(url).is_none());
}

const TMPL_KEYS: &[&str] = &["URL", "User-ID", "Password", "Comment"];

fn tmpl_keys() -> Vec<String> {
    TMPL_KEYS.iter().map(|s| s.to_string()).collect()
}

#[test]
fn test_template_parse_basic() {
    let entry = String::from(format!("URL{}https://example.com\nUser-ID{}john\nPassword{}secret\nComment{}none\n", TEMPLATE_SEP, TEMPLATE_SEP, TEMPLATE_SEP, TEMPLATE_SEP));
    let (values, counts) = parse_entry(&entry, &tmpl_keys());
    assert_eq!(values.get("URL").unwrap(), "https://example.com");
    assert_eq!(values.get("User-ID").unwrap(), "john");
    assert_eq!(values.get("Password").unwrap(), "secret");
    assert_eq!(values.get("Comment").unwrap(), "none");
    assert!(counts.values().all(|&c| c == 1));
}

#[test]
fn test_template_parse_missing_key() {
    let entry = String::from(format!("URL{}https://example.com\nPassword{}secret\n", TEMPLATE_SEP, TEMPLATE_SEP));
    let (values, counts) = parse_entry(&entry, &tmpl_keys());
    assert_eq!(values.len(), 2);
    assert!(values.contains_key("URL"));
    assert!(values.contains_key("Password"));
    assert!(!values.contains_key("User-ID"));
    assert!(!counts.contains_key("User-ID"));
}

#[test]
fn test_template_parse_duplicate_keeps_last() {
    let entry = String::from(format!("URL{}https://first.com\nURL{}https://last.com\n", TEMPLATE_SEP, TEMPLATE_SEP));
    let keys = vec![String::from("URL")];
    let (values, counts) = parse_entry(&entry, &keys);
    assert_eq!(values.get("URL").unwrap(), "https://last.com");
    assert_eq!(counts.get("URL").unwrap(), &2);
}

#[test]
fn test_template_parse_empty_entry() {
    let entry = String::from("");
    let (values, counts) = parse_entry(&entry, &tmpl_keys());
    assert!(values.is_empty());
    assert!(counts.is_empty());
}

#[test]
fn test_template_parse_separator_only() {
    let entry = String::from(format!("Password{}\n", TEMPLATE_SEP));
    let (values, counts) = parse_entry(&entry, &tmpl_keys());
    assert!(values.is_empty());
    assert!(counts.is_empty());
}

#[test]
fn test_template_parse_no_matching_keys() {
    let entry = String::from("Some random text\nNo key value pairs here\n");
    let (values, counts) = parse_entry(&entry, &tmpl_keys());
    assert!(values.is_empty());
    assert!(counts.is_empty());
}

#[test]
fn test_template_parse_prefix_no_false_match() {
    let entry = String::from(format!("Password-hint{}something\n", TEMPLATE_SEP));
    let keys = vec![String::from("Password")];
    let (values, counts) = parse_entry(&entry, &keys);
    assert!(values.is_empty());
    assert!(counts.is_empty());
}

#[test]
fn test_template_parse_value_whitespace_trimmed() {
    let entry = String::from(format!("  URL{} https://example.com   \n", TEMPLATE_SEP));
    let keys = vec![String::from("URL")];
    let (values, counts) = parse_entry(&entry, &keys);
    assert_eq!(values.get("URL").unwrap(), "https://example.com");
    assert_eq!(counts.get("URL").unwrap(), &1);
}
