/* Copyright 2021 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use rand::RngCore;
use base64;
use std::io::{Error, ErrorKind};
use rand::Rng;

use crate::PW_MAX_SEC_LEVEL;


#[derive(Debug, Hash, PartialEq, Eq)]
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

// This password generator aims to create pronouncable passwords which consist of
// the following elements: A sequence of two letter groups which consist of a consonant
// followed by a vowel. There are 420 such groups. Therefore when selecting one of these
// groups at random each one contains 8.7 bits of entropy. The final four character group
// is a consonant followed by a three digit number. There are 26*1000 such four character 
// groups so it has an entropy of 14.6 Bits when one is chosen randomly.
pub struct SpecialGenerator {
    rng: rand::prelude::ThreadRng,
}

const CONSONANTS: &str = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";
const VOWELS: &str = "aeiouAEIOU";

impl SpecialGenerator {
    pub fn new() -> SpecialGenerator {
        return SpecialGenerator {
            rng: rand::thread_rng()
        }
    }

    fn get_group(&mut self) -> String {       
        let pos1 = self.rng.gen_range(0..42);
        let pos2 = self.rng.gen_range(0..10);

        let mut res = String::from(&CONSONANTS[pos1..pos1+1]);
        res.push_str(&VOWELS[pos2..pos2+1]);

        return res;
    }
}

impl PasswordGenerator for SpecialGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        let security_level: f64 = (8 * num_bytes) as f64;
        let number_of_groups = (security_level - 14.6) / 8.7;
        let number_of_groups: usize = number_of_groups.ceil() as usize;
        let mut res = String::from("");

        for _ in 0..number_of_groups {
            res.push_str(&self.get_group())
        }

        let pos1 = self.rng.gen_range(0..42);
        res.push_str(&CONSONANTS[pos1..pos1+1]);
        res.push_str(&format!("{:03}", self.rng.gen_range(0..1000)));

        return Some(res);
    }
}