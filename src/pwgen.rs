use rand::RngCore;
use base64;
use crate::PW_MAX_SEC_LEVEL;


#[derive(Debug)]
pub enum GenerationStrategy {
    Base64,
    Hex,
    Special
}

pub trait PasswordGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String>;
}

pub struct B64Generator {
    rng: rand::prelude::ThreadRng,
    buffer: [u8; PW_MAX_SEC_LEVEL]
}

impl B64Generator {
    pub fn new() ->  B64Generator {
        return B64Generator {
            rng: rand::thread_rng(), 
            buffer: [0; PW_MAX_SEC_LEVEL]
        }
    }
}

impl PasswordGenerator for B64Generator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        if num_bytes > PW_MAX_SEC_LEVEL {
            return None;
        }

        match self.rng.try_fill_bytes(&mut self.buffer) {
            Err(_) => return None,
            _ => ()
        };

        let mut help = base64::encode(&(self.buffer[..num_bytes]));
        help = help.replace("=", "");

        Some(help)
    }
}

pub struct HexGenerator {
    rng: rand::prelude::ThreadRng,
    buffer: [u8; PW_MAX_SEC_LEVEL]
}

impl HexGenerator {
    pub fn new() ->  HexGenerator {
        return HexGenerator {
            rng: rand::thread_rng(), 
            buffer: [0; PW_MAX_SEC_LEVEL]
        }
    }
}

impl PasswordGenerator for HexGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        if num_bytes > PW_MAX_SEC_LEVEL {
            return None;
        }

        match self.rng.try_fill_bytes(&mut self.buffer) {
            Err(_) => return None,
            _ => ()
        };

        let mut res = String::from("");
        self.buffer[..num_bytes].into_iter().for_each(|i| res.push_str(&format!("{:02X}", i)));

        Some(res)
    }
}
