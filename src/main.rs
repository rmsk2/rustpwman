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
}
