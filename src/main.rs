mod tests;
mod fcrypt;

fn main() {
    let res = match fcrypt::CryptedData::from_file("safe_test.enc") {
        Err(e) => {
            println!("{}", e);
            return;
        },
        Ok(r) => {
            r
        }
    };

    let plaintext = match res.decrypt("test456") {
        Ok(p) => p,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };

    println!("{:?}", String::from_utf8(plaintext));

    let data: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut cr_data = fcrypt::CryptedData::new(data);
    match cr_data.encrypt("test456") {
        Some(e) => {
            println!("{:?}", e);
            return;
        }
        None => ()
    }
}
