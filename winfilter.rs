use std::io;
use std::io::Read;
use std::io::Write;

fn main() {
    let mut one_char: [u8; 1] = [0];
    let mut other_chars: [u8; 7] = [0,0,0,0,0,0,0];

    io::stdin().read_exact(&mut one_char).unwrap();

    if one_char[0] != 0x1b {
        io::stdout().write_all(&one_char).unwrap();
    } else {
        io::stdin().read_exact(&mut other_chars).unwrap();
    }

    io::copy(&mut io::stdin().lock(), &mut io::stdout().lock()).unwrap();
}