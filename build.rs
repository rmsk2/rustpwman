use rand::Rng;
use std::{fs, path::Path};

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("obfuscator.bin");

    let mut obfuscator = [0u8; 32];
    rand::rng().fill_bytes(&mut obfuscator);
    fs::write(&dest, &obfuscator).unwrap();
}
