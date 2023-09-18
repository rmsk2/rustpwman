use std::io;
use std::io::Read;
use std::io::Write;

fn main() {
    let mut one_char: [u8; 1] = [0];
    let mut other_chars: [u8; 7] = [0,0,0,0,0,0,0];

    // read first byte
    io::stdin().read_exact(&mut one_char).unwrap();

    // Is first byte the ESCAPE character?
    if one_char[0] != 0x1b {
        // No => write the first character to stdout
        io::stdout().write_all(&one_char).unwrap();
    } else {
        // Yes => Assume the following 7 bytes are the rest of the spurious Escape sequence
        // Read them but do not copy them to stdout
        io::stdin().read_exact(&mut other_chars).unwrap();
    }

    // Copy the rest without any filtering
    io::copy(&mut io::stdin().lock(), &mut io::stdout().lock()).unwrap();
}