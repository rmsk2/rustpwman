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
mod tomlconfig;
mod tuiconfig;

use std::env;
use dirs;
use clap::{Arg, App, SubCommand};
use rpassword;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use pwgen::GenerationStrategy;

pub const VERSION_STRING: &'static str = env!("CARGO_PKG_VERSION");
const COMMAND_ENCRYPT: &str = "enc";
const COMMAND_DECRYPT: &str = "dec";
const COMMAND_GUI: &str = "gui";
const COMMAND_CONFIG: &str = "cfg";
const ARG_INPUT_FILE: &str = "inputfile";
const ARG_OUTPUT_FILE: &str = "outputfile";
const ARG_CONFIG_FILE: &str = "cfgfile";
const ARG_KDF: &str = "kdf";
pub const CFG_FILE_NAME: &str = ".rustpwman";

use fcrypt::DEFAULT_KDF_ID;

struct RustPwMan {
    default_deriver: fcrypt::KeyDeriver,
    default_deriver_id: fcrypt::KdfId,
    default_sec_level: usize,
    default_pw_gen: GenerationStrategy
}

impl RustPwMan {
    fn new() -> Self {
        let (default_kdf, _) = DEFAULT_KDF_ID.to_named_func();

        return RustPwMan {
            default_deriver: default_kdf,
            default_deriver_id: DEFAULT_KDF_ID,
            default_sec_level: modtui::PW_SEC_LEVEL,
            default_pw_gen: GenerationStrategy::Base64
        }
    }

    pub fn get_cfg_file_name() -> Option<std::path::PathBuf> {
        let mut home_dir = match dirs::home_dir() {
            Some(p) => p,
            None => return None
        };

        home_dir.push(CFG_FILE_NAME);
        
        return Some(home_dir);
    }

    fn load_config(&mut self) {
        let cfg_file = match RustPwMan::get_cfg_file_name() {
            Some(p) => p,
            None => return
        };

        let loaded_config = match tomlconfig::load(&cfg_file) {
            Ok(c) => c,
            Err(_) => return
        };

        let (k, id) = self.str_to_deriver(&loaded_config.pbkdf[..]);

        self.default_deriver = k;
        self.default_deriver_id = id;
        self.default_pw_gen = self.str_to_gen_strategy(&loaded_config.pwgen[..]);
        self.default_sec_level = self.verify_sec_level(loaded_config.seclevel);
    }

    fn str_to_gen_strategy(&self, strategy_name: &str) -> GenerationStrategy {
        return match GenerationStrategy::from_str(strategy_name) {
            Some(v) => v,
            _ => self.default_pw_gen
        };       
    }

    fn verify_sec_level(&self, loaded_level: usize) -> usize {
        if loaded_level >= modtui::PW_MAX_SEC_LEVEL {
            self.default_sec_level
        } 
        else
        {
            loaded_level
        }
    }

    fn str_to_deriver(&self, deriver_name: &str) -> (fcrypt::KeyDeriver, fcrypt::KdfId) {
        return match fcrypt::KdfId::from_str(deriver_name) {
            Some(v) => v.to_named_func(),
            _ => (self.default_deriver, self.default_deriver_id)
        }       
    }

    fn set_pbkdf_from_command_line(&mut self, matches: &clap::ArgMatches) {    
        if matches.is_present(ARG_KDF) {
            let mut kdf_names: Vec<String> = Vec::new();
            if let Some(names) = matches.values_of(ARG_KDF) {
                names.for_each(|x| kdf_names.push(String::from(x)));
            }
            
            let (k, id) = self.str_to_deriver(&kdf_names[0][..]);

            self.default_deriver = k;
            self.default_deriver_id = id;
        }
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
    
    fn perform_encrypt_command(&mut self, encrypt_matches: &clap::ArgMatches) {
        self.set_pbkdf_from_command_line(encrypt_matches);
        let (file_in, file_out) = RustPwMan::determine_in_out_files(encrypt_matches);
        
        let pw = match RustPwMan::enter_password_verified() {
            Err(e) => { 
                println!("Error reading password: {:?}", e);
                return;
            },
            Ok(p) => p
        };
    
        let mut jots_file = jots::Jots::new(self.default_deriver, self.default_deriver_id);
    
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
    
    fn perform_decrypt_command(&mut self, decrypt_matches: &clap::ArgMatches) {
        self.set_pbkdf_from_command_line(decrypt_matches);
        let (file_in, file_out) = RustPwMan::determine_in_out_files(decrypt_matches);
        
        let mut jots_file = jots::Jots::new(self.default_deriver, self.default_deriver_id);
    
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
    
    fn perform_gui_command(&mut self, gui_matches: &clap::ArgMatches) {
        self.set_pbkdf_from_command_line(gui_matches);
    
        let mut file_names: Vec<String> = Vec::new();
        if let Some(in_files) = gui_matches.values_of(ARG_INPUT_FILE) {
            in_files.for_each(|x| file_names.push(String::from(x)));
        }
    
        let data_file_name = file_names[0].clone();
    
        modtui::main_gui(data_file_name, self.default_sec_level, self.default_deriver, self.default_deriver_id, self.default_pw_gen);
    }

    fn perform_config_command(&mut self, config_matches: &clap::ArgMatches) {
        let config_file_name: std::path::PathBuf;
        
        if config_matches.is_present(ARG_CONFIG_FILE) {
            let mut file_names: Vec<String> = Vec::new();

            if let Some(in_files) = config_matches.values_of(ARG_CONFIG_FILE) {
                in_files.for_each(|x| file_names.push(String::from(x)));
            }

            config_file_name = std::path::PathBuf::from(file_names[0].clone());
        } 
        else 
        {
            config_file_name = match RustPwMan::get_cfg_file_name() {
                Some(p) => p,
                None => {
                    println!("Unable to determine config file!");
                    return;
                }
            };
        }

        let loaded_config = match tomlconfig::load(&config_file_name) {
            Ok(c) => c,
            Err(_) => {
                tomlconfig::RustPwManSerialize {
                    seclevel: self.default_sec_level,
                    pbkdf: self.default_deriver_id.to_string(),
                    pwgen: self.default_pw_gen.to_string()
                }
            }
        };

        let sec_level = self.verify_sec_level(loaded_config.seclevel);
        let pw_gen_strategy = self.str_to_gen_strategy(&loaded_config.pwgen);
        let (_, pbkdf_id) = self.str_to_deriver(&loaded_config.pbkdf);


        tuiconfig::config_main(config_file_name, sec_level, pw_gen_strategy, pbkdf_id);
    }    
}

pub fn add_kdf_param() -> clap::Arg<'static, 'static> {
    let mut arg = Arg::with_name(ARG_KDF);

    arg = arg.long(ARG_KDF);
    arg = arg.takes_value(true);
    arg = arg.help("Use specific PBKDF");
    let ids: Vec<fcrypt::KdfId> = fcrypt::KdfId::get_known_ids();

    for i in ids {
        arg = arg.possible_value(i.to_str());
    }

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
                .arg(add_kdf_param()))
        .subcommand(
            SubCommand::with_name(COMMAND_CONFIG)
                .about("Change configuration")        
                .arg(Arg::with_name(ARG_CONFIG_FILE)
                    .short("c")
                    .long(ARG_CONFIG_FILE)
                    .takes_value(true)
                    .help("Name of config file. Default is .rustpwman")));                    

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
        (COMMAND_CONFIG, Some(cfg_matches)) => {
            rustpwman.perform_config_command(cfg_matches);
        },      
        _ => {
            match app.print_long_help() {
                Err(e) => eprintln!("{}", e),
                _ => eprintln!("")
            }
        }
    };
}