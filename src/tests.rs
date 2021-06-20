#[cfg(test)]
use crate::fcrypt;
#[cfg(test)]
use crate::jots;

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
        let mut j = jots::Jots::new();
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

    let mut j2 = jots::Jots::new();
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
    
    let mut j = jots::Jots::new();
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