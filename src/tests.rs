#[cfg(test)]
use crate::fcrypt;


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

    if !plain_again.eq(&data_raw) {
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

    if !plain_again.eq(&data_raw) {
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

    if !plain_again.eq(&data_raw) {
        panic!("Decryption result differs from original plaintext");
    }
}