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

use rand::Rng;

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
            GenerationStrategy::Base64 => &|| { return Box::new(NumDigitGenerator::base64()) },
            GenerationStrategy::Hex => &|| { return Box::new(NumDigitGenerator::new(&vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'])) },
            GenerationStrategy::Special => &|| { return Box::new(SpecialGenerator::new(false)) },
            GenerationStrategy::Numeric => &|| { return Box::new(NumDigitGenerator::new(&vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'])) },
            GenerationStrategy::Custom => &|| { return Box::new(NumDigitGenerator::new(&vec!['a', 'b'])) }
        }
    }

    pub fn to_str(self) -> &'static str {
        match self {
            GenerationStrategy::Base64 => GEN_BASE64,
            GenerationStrategy::Hex => GEN_HEX,
            GenerationStrategy::Special => GEN_SPECIAL,
            GenerationStrategy::Numeric => GEN_NUMERIC,
            GenerationStrategy::Custom => GEN_CUSTOM
        }
    }

    pub fn to_string(self) -> String {
        return String::from(self.to_str());
    }

    pub fn get_known_ids() -> Vec<GenerationStrategy> {
        return vec![GenerationStrategy::Base64, GenerationStrategy::Hex, GenerationStrategy::Special, GenerationStrategy::Numeric];
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
            rng: rand::rng(),
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
        let pos1 = self.rng.random_range(0..self.consonants.len());
        let pos2 = self.rng.random_range(0..self.vowels.len());

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

        let pos1 = self.rng.random_range(0..42);
        res.push_str(&self.consonants[pos1]);
        res.push_str(&format!("{:03}", self.rng.random_range(0..1000)));

        return Some(res);
    }
}

pub struct NumDigitGenerator {
    rng: rand::prelude::ThreadRng,
    digits: Vec<char>
}

impl NumDigitGenerator {
    pub fn new(d: &Vec<char>) -> NumDigitGenerator {
        if d.len() < 2 {
            panic!("Not a valid selection of chars")
        }

        return NumDigitGenerator {
            rng: rand::rng(),
            digits: d.clone(),
        }
    }

    pub fn base64() -> NumDigitGenerator {
        let upper_chars = String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ");

        let mut all_chars = upper_chars + "abcdefghijklmnopqrstuvwxyz";
        all_chars = all_chars + "0123456789";
        all_chars = all_chars + "$!";

        return NumDigitGenerator::new(&all_chars.chars().collect());
    }

    pub fn sec_level_in_digits(&self, sec_level_in_bits: usize) -> usize {
        ((sec_level_in_bits as f64) / (self.digits.len() as f64).log2()).ceil() as usize
    }
}

impl PasswordGenerator for NumDigitGenerator {
    fn gen_password(&mut self, num_bytes: usize) -> Option<String> {
        let mut res = String::from("");

        for _ in 0..self.sec_level_in_digits(num_bytes * 8) {
            let rand_digit = self.rng.random_range(0..self.digits.len());
            res.push(self.digits[rand_digit])
        }

        return Some(res);
    }

    fn set_custom(&mut self, s: &String) {
        if s.len() < 2 {
            panic!("Not a valid selection of chars")
        }

        self.digits = s.chars().collect();
    }
}
