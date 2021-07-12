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

mod tests;
mod fcrypt;
mod jots;
mod pwgen;
mod modtui;

use std::env;
use clap::{Arg, App, SubCommand};
use rpassword;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use toml;

pub const VERSION_STRING: &'static str = env!("CARGO_PKG_VERSION");
const COMMAND_ENCRYPT: &str = "enc";
const COMMAND_DECRYPT: &str = "dec";
const COMMAND_GUI: &str = "gui";
const ARG_INPUT_FILE: &str = "inputfile";
const ARG_OUTPUT_FILE: &str = "outputfile";
const ARG_KDF: &str = "kdf";
const KDF_SCRYPT: &str = "scrypt";
const KDF_BCRYPT: &str = "bcrypt";
const KDF_ARGON2: &str = "argon2";
const KDF_SHA256: &str = "sha256";

const SEC_BIT_ENV_VAR: &str = "RUSTPWMAN_SEC_BITS";
const DEFAULT_KDF: fcrypt::KeyDeriver = fcrypt::GcmContext::sha256_deriver;

struct RustPwMan {
    default_deriver: fcrypt::KeyDeriver,
    config_data: Option<toml::Value>
}

impl RustPwMan {
    fn new() -> Self {
        return RustPwMan {
            default_deriver: DEFAULT_KDF,
            config_data: None
        }
    }

    fn load_config(&mut self) {
        self.config_data = None
    }

    pub fn determine_sec_level() -> usize {
        return match env::var(SEC_BIT_ENV_VAR)  {
            Ok(s) => {
                match s.parse::<usize>() {
                    Err(_) => modtui::PW_SEC_LEVEL,
                    Ok(b) => {
                        if b < modtui::PW_MAX_SEC_LEVEL {
                            b
                        } else {
                            modtui::PW_SEC_LEVEL
                        }
                    }
                }
            },
            Err(_) => {
                modtui::PW_SEC_LEVEL
            } 
        };
    } 

    fn determine_pbkdf(&self, matches: &clap::ArgMatches) -> fcrypt::KeyDeriver {
        let derive = self.default_deriver;
    
        if matches.is_present(ARG_KDF) {
            let mut kdf_names: Vec<String> = Vec::new();
            if let Some(names) = matches.values_of(ARG_KDF) {
                names.for_each(|x| kdf_names.push(String::from(x)));
            }
            
            return match &kdf_names[0][..] {
                KDF_SCRYPT => fcrypt::GcmContext::scrypt_deriver,
                KDF_BCRYPT => fcrypt::GcmContext::bcrypt_deriver,
                KDF_ARGON2 => fcrypt::GcmContext::argon2id_deriver,
                KDF_SHA256 => fcrypt::GcmContext::sha256_deriver,
                _ => derive
            };
        }
    
        return derive;
    }
    
    fn determine_in_out_files(matches: &clap::ArgMatches) -> (String, String) {
        let mut file_names_in: Vec<String> = Vec::new();
        if let Some(in_files) = matches.values_of(ARG_INPUT_FILE) {
            in_files.for_each(|x| file_names_in.push(String::from(x)));
        }
        
        let mut file_names_out: Vec<String> = Vec::new();
        if let Some(out_files) = matches.values_of(ARG_OUTPUT_FILE) {
            out_files.for_each(|x| file_names_out.push(String::from(x)));
        }
    
        return (file_names_in[0].clone(), file_names_out[0].clone());
    }
    
    fn enter_password_verified() -> std::io::Result<String> {
        let pw1 = rpassword::read_password_from_tty(Some("Password: "))?;
        let pw2 = rpassword::read_password_from_tty(Some("Verfication: "))?;
    
        if pw1 != pw2 {
            return Err(Error::new(ErrorKind::Other, "Passwords differ"));
        }
    
        match fcrypt::GcmContext::check_password(&pw1) {
            Some(e) => return Err(e),
            None => ()
        }
    
        return Ok(pw1);
    }
    
    fn perform_encrypt_command(&self, encrypt_matches: &clap::ArgMatches) {
        let derive: fcrypt::KeyDeriver = self.determine_pbkdf(encrypt_matches);
        let (file_in, file_out) = RustPwMan::determine_in_out_files(encrypt_matches);
        
        let pw = match RustPwMan::enter_password_verified() {
            Err(e) => { 
                println!("Error reading password: {:?}", e);
                return;
            },
            Ok(p) => p
        };
    
        let mut jots_file = jots::Jots::new(derive);
    
        let file = match File::open(&file_in) {
            Ok(f) => f,
            Err(e) => {
                println!("Error opening file. {:?}", e);
                return;                    
            }
        };
    
        let reader = BufReader::new(file);
        
        match jots_file.from_reader(reader) {
            Err(e) => {
                println!("Error reading file. {:?}", e);
                return;                    
            },
            Ok(_) => ()                
        }
    
        match jots_file.to_enc_file(&file_out, &pw[..]) {
            Ok(_) => (),
            Err(e) => { 
                println!("Error creating file. {:?}", e);
                return;
            },
        };
    }
    
    fn perform_decrypt_command(&self, decrypt_matches: &clap::ArgMatches) {
        let derive: fcrypt::KeyDeriver = self.determine_pbkdf(decrypt_matches);
        let (file_in, file_out) = RustPwMan::determine_in_out_files(decrypt_matches);
        
        let mut jots_file = jots::Jots::new(derive);
    
        let pw = match rpassword::read_password_from_tty(Some("Password: ")) {
            Err(_) => { 
                println!("Error reading password");
                return;
            },
            Ok(p) => p
        };
        
        match fcrypt::GcmContext::check_password(&pw) {
            Some(e) => {
                println!("Password illegal: {:?}", e);
                return;
            },
            None => ()
        }    
        
        println!();
    
        match jots_file.from_enc_file(&file_in, &pw[..]) {
            Err(e) => {
                println!("Error reading file. {:?}", e);
                return;                    
            },
            Ok(_) => ()
        };
    
        let file = match File::create(&file_out) {
            Err(e) => {
                println!("Error creating file. {:?}", e);
                return;                    
            },
            Ok(f) => f      
        };
    
        let w = BufWriter::new(file);
    
        match jots_file.to_writer(w) {
            Err(e) => {
                println!("Error writing file. {:?}", e);
                return;                    
            },
            Ok(_) => ()
        };
    }
    
    fn perform_gui_command(&self, gui_matches: &clap::ArgMatches) {
        let derive: fcrypt::KeyDeriver = self.determine_pbkdf(gui_matches);
    
        let mut file_names: Vec<String> = Vec::new();
        if let Some(in_files) = gui_matches.values_of(ARG_INPUT_FILE) {
            in_files.for_each(|x| file_names.push(String::from(x)));
        }
    
        let data_file_name = file_names[0].clone();
        let default_sec_bits = RustPwMan::determine_sec_level();
    
        modtui::main_gui(data_file_name, default_sec_bits, derive, pwgen::GenerationStrategy::Special);
    }
}


pub fn add_kdf_param() -> clap::Arg<'static, 'static> {
    let mut arg = Arg::with_name(ARG_KDF);

    arg = arg.long(ARG_KDF);
    arg = arg.takes_value(true);
    arg = arg.help("Use specific PBKDF");
    arg = arg.possible_value(KDF_SCRYPT);
    arg = arg.possible_value(KDF_BCRYPT);
    arg = arg.possible_value(KDF_ARGON2);
    arg = arg.possible_value(KDF_SHA256);

    return arg;
}

fn main() {
    let mut app = App::new("rustpwman")
        .version(VERSION_STRING)
        .author("Martin Grap <rmsk2@gmx.de>")
        .about("A password manager for the cursive TUI in Rust")          
        .subcommand(
            SubCommand::with_name(COMMAND_ENCRYPT)
                .about("Encrypt file")        
                .arg(Arg::with_name(ARG_INPUT_FILE)
                    .short("i")
                    .long(ARG_INPUT_FILE)
                    .takes_value(true)
                    .required(true)
                    .help("Name of plaintext file to encrypt"))
                .arg(Arg::with_name(ARG_OUTPUT_FILE)
                    .short("o")
                    .long(ARG_OUTPUT_FILE)
                    .required(true)
                    .takes_value(true)
                    .help("Encrypted output file"))                    
                .arg(add_kdf_param()))
        .subcommand(
            SubCommand::with_name(COMMAND_DECRYPT)
                .about("Decrypt file")        
                .arg(Arg::with_name(ARG_INPUT_FILE)
                    .short("i")
                    .long(ARG_INPUT_FILE)
                    .required(true)
                    .takes_value(true)
                    .help("Name of encrypted file"))
                .arg(Arg::with_name(ARG_OUTPUT_FILE)
                    .short("o")
                    .long(ARG_OUTPUT_FILE)
                    .required(true)
                    .takes_value(true)
                    .help("Name of plaintext file"))                    
                .arg(add_kdf_param()))
        .subcommand(
            SubCommand::with_name(COMMAND_GUI)
                .about("Open file in TUI")        
                .arg(Arg::with_name(ARG_INPUT_FILE)
                    .short("i")
                    .long(ARG_INPUT_FILE)
                    .required(true)
                    .takes_value(true)
                    .help("Name of encrypted data file"))                   
                .arg(add_kdf_param()));                    

    let mut rustpwman = RustPwMan::new();
    rustpwman.load_config();

    let matches = app.clone().get_matches();
    let subcommand = matches.subcommand();

    match subcommand {
        (COMMAND_ENCRYPT, Some(encrypt_matches)) => {
            rustpwman.perform_encrypt_command(encrypt_matches);
        },
        (COMMAND_DECRYPT, Some(decrypt_matches)) => {
            rustpwman.perform_decrypt_command(decrypt_matches);
        },
        (COMMAND_GUI, Some(gui_matches)) => {
            rustpwman.perform_gui_command(gui_matches);
        },        
        _ => {
            match app.print_long_help() {
                Err(e) => eprintln!("{}", e),
                _ => eprintln!("")
            }
        }
    };
}