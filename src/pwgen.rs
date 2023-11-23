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

#![allow(dead_code)]

use rand::RngCore;
use base64;
use std::io::{Error, ErrorKind};
use rand::Rng;
use num_bigint::BigUint;

use crate::modtui::PW_MAX_SEC_LEVEL;
const GEN_BASE64: &str = "base64";
const GEN_HEX: &str = "hex";
const GEN_SPECIAL: &str = "special";
const GEN_NUMERIC: &str = "numeric";
const GEN_CUSTOM: &str = "custom";

pub trait PasswordGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String>;
    fn set_custom(&mut self, _s: &String) {}
}

type StrategyCreator = dyn Fn() -> Box<dyn PasswordGenerator>;

#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone)]
pub enum GenerationStrategy {
    Base64,
    Hex,
    Special,
    Numeric,
    Custom
}

impl GenerationStrategy {
    pub fn from_str(name: &str) -> Option<Self> {
        return match name {
            GEN_BASE64 => Some(GenerationStrategy::Base64),
            GEN_HEX => Some(GenerationStrategy::Hex),
            GEN_SPECIAL => Some(GenerationStrategy::Special),
            GEN_NUMERIC => Some(GenerationStrategy::Numeric),
            GEN_CUSTOM => Some(GenerationStrategy::Custom),
            _ => None
        };  
    }

    pub fn to_creator(self) -> &'static StrategyCreator {
        return match self {
            GenerationStrategy::Base64 => &|| { return Box::new(B64Generator::new()) },
            GenerationStrategy::Hex => &|| { return Box::new(HexGenerator::new()) },
            GenerationStrategy::Special => &|| { return Box::new(SpecialGenerator::new(false)) },
            GenerationStrategy::Numeric => &|| { return Box::new(NumericGenerator::new()) },
            GenerationStrategy::Custom => &|| { return Box::new(BaseNGenerator::new(&vec!['a', 'b'])) },
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            GenerationStrategy::Base64 => GEN_BASE64,
            GenerationStrategy::Hex => GEN_HEX,
            GenerationStrategy::Special => GEN_SPECIAL,
            GenerationStrategy::Numeric => GEN_NUMERIC,
            GenerationStrategy::Custom => GEN_CUSTOM,
        }
    }

    pub fn to_string(self) -> String {
        return String::from(self.to_str());
    }

    pub fn get_known_ids() -> Vec<GenerationStrategy> {
        return vec![GenerationStrategy::Base64, GenerationStrategy::Hex, GenerationStrategy::Special, GenerationStrategy::Numeric];
    }    
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
        help = help.replace("/", "$");
        help = help.replace("+", "!");

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
// is a consonant followed by a three digit number. There are 52*1000 such four character 
// groups so it has an entropy of 15.6 Bits when one is chosen randomly.
//
// When setting use_hissing_sounds to true sch and ch are used as additional consonants,
// which they in essence are in the german language. After implementing this feature it 
// became apparent though that this is not really practical. 
pub struct SpecialGenerator {
    rng: rand::prelude::ThreadRng,
    use_ch: bool,
    vowels: Vec<String>,
    consonants: Vec<String>,
    entropy_per_group: f64,
    entropy_in_last_group: f64
}

const ALL_CONSONANTS: &str = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";
const ALL_VOWELS: &str = "aeiouAEIOU";

impl SpecialGenerator {
    pub fn new(use_hissing_sounds: bool) -> SpecialGenerator {
        let mut res = SpecialGenerator {
            rng: rand::thread_rng(),
            use_ch: use_hissing_sounds,
            vowels: Vec::new(),
            consonants: Vec::new(),
            entropy_per_group: 8.7,
            entropy_in_last_group: 15.6
        };        
        
        let hc = String::from(ALL_CONSONANTS);
        let hv = String::from(ALL_VOWELS);

        hc.chars().for_each(|i| res.consonants.push(String::from(i)));
        hv.chars().for_each(|i| res.vowels.push(String::from(i)));

        if res.use_ch {
            res.consonants.push(String::from("ch"));
            res.consonants.push(String::from("Ch"));
            res.consonants.push(String::from("CH"));
            res.consonants.push(String::from("cH"));

            res.consonants.push(String::from("sch"));
            res.consonants.push(String::from("sCh"));
            res.consonants.push(String::from("sCH"));
            res.consonants.push(String::from("scH"));

            res.consonants.push(String::from("Sch"));
            res.consonants.push(String::from("SCh"));
            res.consonants.push(String::from("SCH"));
            res.consonants.push(String::from("ScH"));                        
        }

        res.entropy_per_group = ((res.consonants.len() * res.vowels.len()) as f64).log2();
        res.entropy_in_last_group = ((res.consonants.len() * 1000) as f64).log2();

        return res;
    }

    fn get_group(&mut self) -> String {       
        let pos1 = self.rng.gen_range(0..self.consonants.len());
        let pos2 = self.rng.gen_range(0..self.vowels.len());

        let mut res = self.consonants[pos1].clone();
        res.push_str(&self.vowels[pos2]);

        return res;
    }
}

impl PasswordGenerator for SpecialGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        let security_level: f64 = (8 * num_bytes) as f64;
        let number_of_groups = (security_level - self.entropy_in_last_group) / self.entropy_per_group;
        let number_of_groups: usize = number_of_groups.ceil() as usize;
        let mut res = String::from("");

        for _ in 0..number_of_groups {
            res.push_str(&self.get_group())
        }

        let pos1 = self.rng.gen_range(0..42);
        res.push_str(&self.consonants[pos1]);
        res.push_str(&format!("{:03}", self.rng.gen_range(0..1000)));

        return Some(res);
    }
}

pub struct NumericGenerator (GeneratorBase);

impl NumericGenerator {
    pub fn new() -> NumericGenerator {
        return NumericGenerator(GeneratorBase::new())
    }
}

impl PasswordGenerator for NumericGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        let digits = vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
        let security_level: f64 = (8 * num_bytes) as f64;
        let sec_level_in_decimal = security_level / 3.32;
        let number_of_digits: usize = sec_level_in_decimal.ceil() as usize;
        let mut res = String::from("");

        for _ in 0..number_of_digits {
            let rand_digit = self.0.rng.gen_range(0..10);
            res.push(digits[rand_digit])
        }

        return Some(res);
    }    
}

pub struct BaseNGenerator {
    base: GeneratorBase,
    digits: Vec<char>,
    zero_digit: String
}

impl BaseNGenerator {
    pub fn new(d: &Vec<char>) -> BaseNGenerator {            
        if d.len() < 2 {
            panic!("Not a valid radix")
        }

        let mut zero = String::from("");
        zero.push(d[0]);

        return BaseNGenerator { 
            base: GeneratorBase::new(), 
            digits: d.clone(),
            zero_digit: zero,
        }
    }

    pub fn get_max_digits(&self, num_bytes: usize) -> usize {
        // determine max length of generated value in order to spot leading
        // zeros further on.
        let len_test: [u8; PW_MAX_SEC_LEVEL] = [0xFF; PW_MAX_SEC_LEVEL];
        let j = BigUint::from_bytes_be(&len_test[..num_bytes]);

        return j.to_radix_be(self.digits.len() as u32).len();
    }

    pub fn from_string(s: &String) -> BaseNGenerator {
        let mut res = BaseNGenerator::new(&vec!['a', 'b']);
        res.set_custom(s);
        
        return res;
    }

    pub fn buf_to_base_n(&self, base_256_num: &[u8], num_bytes: usize) -> String {
        let i = BigUint::from_bytes_be(base_256_num);
        // perform radix conversion using self.digits.len() as the base
        let raw_digits = i.to_radix_be(self.digits.len() as u32);

        // transform numeric values for digits to actual characters
        let mut res = String::from("");
        for i in raw_digits {
            res.push(self.digits[i as usize]);
        }

        let max_len = self.get_max_digits(num_bytes);

        // add leading zeros if neccessary
        while res.len() < max_len {
            res.insert_str(0, &self.zero_digit);
        }

        return res;
    }
}

impl PasswordGenerator for BaseNGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        let _ = match self.base.fill_buffer(num_bytes) {
            Err(_) => return None,
            Ok(b) => b 
        };        
        
        let res = self.buf_to_base_n(&self.base.buffer[..num_bytes], num_bytes);

        return Some(res);
    }

    fn set_custom(&mut self, s: &String) {
        let mut v: Vec<char> = vec![];

        for i in s.chars() {
            v.push(i);
        }
        
        self.digits = v.clone();
        self.zero_digit = String::from("");
        self.zero_digit.push(v[0]);
    }
}