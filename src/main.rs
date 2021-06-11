mod tests;
mod fcrypt;
mod jots;

fn main() {
    let mut ctx = fcrypt::GcmContext::new();

    let data = match ctx.from_file("safe_test.enc") {
        Err(e) => {
            println!("{}", e);
            return;
        },
        Ok(r) => {
            r
        }
    };

    let plaintext = match ctx.decrypt("test456", &data) {
        Ok(p) => p,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };

    let mut j = jots::Jots::new();
    match j.from_reader(plaintext.as_slice()) {
        Ok(_) => {
            j.print();
        }
        Err(e) => {
            println!("{:?}", e);
            return;
        }        
    };

    let mut v: Vec<u8> = Vec::new();
    match j.to_writer(&mut v) {
        Ok(_) => {
            println!("{:?}", String::from_utf8(v).unwrap());
        }
        Err(e) => {
            println!("{:?}", e);
            return;
        }         
    };

    let data: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let cipher_text = match ctx.encrypt("test456", &data) {
        Ok(cipher_text) => {
            cipher_text
        }
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };

    match ctx.to_file(&cipher_text, "dummy.enc") {
        Ok(_) => {
        }
        Err(e) => {
            println!("{:?}", e);
            return;
        }        
    }
}
