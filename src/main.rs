mod tests;
mod fcrypt;

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

    println!("{:?}", String::from_utf8(plaintext));

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
