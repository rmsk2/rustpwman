use rand::RngCore;
use base64;
use std::io::{Error, ErrorKind};
use rand::Rng;

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

pub struct GeneratorBase {
    rng: rand::prelude::ThreadRng,
    buffer: [u8; PW_MAX_SEC_LEVEL]
}

impl GeneratorBase {
    pub fn new() -> GeneratorBase {
        return GeneratorBase {
            rng: rand::thread_rng(), 
            buffer: [0; PW_MAX_SEC_LEVEL]
        }
    }

    pub fn fill_buffer(&mut self, num_bytes: usize) -> Result<&[u8], std::io::Error> {
        if num_bytes > PW_MAX_SEC_LEVEL {
            return Err(Error::new(ErrorKind::Other, "Security level not supported"));
        }

        return match self.rng.try_fill_bytes(&mut self.buffer) {
            Err(_) => Err(Error::new(ErrorKind::Other, "Unable to generate random bytes")),
            Ok(_) => Ok(&self.buffer[..num_bytes])
        };
    }
}

pub struct B64Generator ( GeneratorBase );

impl B64Generator {
    pub fn new() ->  B64Generator {
        return B64Generator (GeneratorBase::new())
    }
}

impl PasswordGenerator for B64Generator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        let buf = match self.0.fill_buffer(num_bytes) {
            Err(_) => return None,
            Ok(b) => b 
        };

        let mut help = base64::encode(buf);
        help = help.replace("=", "");

        Some(help)
    }
}

pub struct HexGenerator ( GeneratorBase );

impl HexGenerator {
    pub fn new() ->  HexGenerator {
        return HexGenerator (GeneratorBase::new())
    }
}

impl PasswordGenerator for HexGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        let buf = match self.0.fill_buffer(num_bytes) {
            Err(_) => return None,
            Ok(b) => b 
        };

        let mut res = String::from("");
        buf.into_iter().for_each(|i| res.push_str(&format!("{:02X}", i)));

        Some(res)
    }
}

pub struct SpecialGenerator {
    rng: rand::prelude::ThreadRng
}

impl SpecialGenerator {
    pub fn new() -> SpecialGenerator {
        return SpecialGenerator {
            rng: rand::thread_rng()
        }
    }

    fn get_group(&mut self) -> String {
        let consonants = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";
        let vowels = "aeiouAEIOU";        
        let pos1 = self.rng.gen_range(0..42);
        let pos2 = self.rng.gen_range(0..10);

        let mut res = String::from(&consonants[pos1..pos1+1]);
        res.push_str(&vowels[pos2..pos2+1]);

        return res;
    }
}

impl PasswordGenerator for SpecialGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        let security_level: f64 = (8 * num_bytes) as f64;
        let number_of_groups = (security_level - 13.0) / 8.7;
        let number_of_groups: usize = number_of_groups.ceil() as usize;
        let mut res = String::from("");

        for _ in 0..number_of_groups {
            res.push_str(&self.get_group())
        }

        res.push_str(&format!("{:04}", self.rng.gen_range(0..10000)));

        return Some(res);
    }
}