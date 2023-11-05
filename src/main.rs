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
mod derivers;
mod jots;
mod pwgen;
mod modtui;
mod tomlconfig;
mod tuiconfig;
mod tuigen;
mod clip;
mod undo;
mod persist;
mod obfuscate;
#[cfg(feature = "webdav")]
mod webdav;
#[cfg(feature = "pwmanclient")]
mod pwman_client;
#[cfg(feature = "pwmanclientux")]
mod pwman_client_ux;
#[cfg(feature = "pwmanclientwin")]
mod pwman_client_win;

const OBFUSCATION_ENV_VAR: &str = "RUSTPWMAN_OBFUSCATION";

use std::env;
use dirs;
use clap::{Arg, Command};
use modtui::DEFAULT_PASTE_CMD;
use modtui::DEFAULT_COPY_CMD;
use persist::PersistCreator;
use persist::Persister;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use pwgen::GenerationStrategy;
use obfuscate::de_obfuscate;
use obfuscate::obfuscate;

pub const VERSION_STRING: &'static str = env!("CARGO_PKG_VERSION");
const COMMAND_ENCRYPT: &str = "enc";
const COMMAND_DECRYPT: &str = "dec";
const COMMAND_GUI: &str = "gui";
const COMMAND_CONFIG: &str = "cfg";
const COMMAND_GENERATE: &str = "gen";
const COMMAND_OBFUSCATE: &str = "obf";
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
    default_pw_gen: GenerationStrategy,
    paste_command: String,
    copy_command: String,
    webdav_user: String,
    webdav_pw: String,
    webdav_server: String
}

impl RustPwMan {
    fn new() -> Self {
        let (default_kdf, _) = DEFAULT_KDF_ID.to_named_func();

        return RustPwMan {
            default_deriver: default_kdf,
            default_deriver_id: DEFAULT_KDF_ID,
            default_sec_level: modtui::PW_SEC_LEVEL,
            default_pw_gen: GenerationStrategy::Base64,
            paste_command: String::from(DEFAULT_PASTE_CMD),
            copy_command: String::from(DEFAULT_COPY_CMD),
            webdav_user: String::from(""),
            webdav_pw: String::from(""),
            webdav_server: String::from(""),
        }
    }

    fn is_option_present(matches: &clap::ArgMatches, id: &str) -> bool {
        let test_res = matches.value_source(id);
    
        return match test_res {
            Some(v) => {
                return v == clap::parser::ValueSource::CommandLine;
            }
            None => false
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

        let mut file_was_read = false;

        let loaded_config = match tomlconfig::load(&cfg_file, &mut file_was_read) {
            Ok(c) => c,
            Err(_) => {
                if file_was_read {
                    panic!("A config file was found but it seems to be corrupt!");
                } else {
                    return;
                }
            }
        };

        let (k, id) = self.str_to_deriver(&loaded_config.pbkdf[..]);

        self.default_deriver = k;
        self.default_deriver_id = id;
        self.default_pw_gen = self.str_to_gen_strategy(&loaded_config.pwgen[..]);
        self.default_sec_level = self.verify_sec_level(loaded_config.seclevel);
        self.paste_command = loaded_config.clip_cmd;
        self.copy_command = loaded_config.copy_cmd;
        self.webdav_user = loaded_config.webdav_user;
        self.webdav_pw = loaded_config.webdav_pw;
        self.webdav_server = loaded_config.webdav_server;
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
        if RustPwMan::is_option_present(matches, ARG_KDF) {
            let a: Option<&String> = matches.get_one(ARG_KDF);
            
            let kdf_name: String = match a {
                Some(b) => b.clone(),
                _ => panic!("Unable to determine KDF") // Should not happen
            };
            
            let (k, id) = self.str_to_deriver(&kdf_name);

            self.default_deriver = k;
            self.default_deriver_id = id;
        }
    }

    fn determine_in_out_files(matches: &clap::ArgMatches) -> (String, String) {
        let in_f: Option<&String> = matches.get_one(ARG_INPUT_FILE);
        let out_f: Option<&String> = matches.get_one(ARG_OUTPUT_FILE);

        let file_name_in = match in_f {
            Some(a) => a.clone(),
            _ => panic!("Unable to determine input file") // Should not happen
        };
        
        let file_name_out = match out_f {
            Some(a) => a.clone(),
            _ => panic!("Unable to determine output file") // Should not happen
        };

        return (file_name_in, file_name_out);
    }
    
    fn enter_password_verified() -> std::io::Result<String> {
        let pw1 = rpassword::prompt_password("Password: ")?;
        let pw2 = rpassword::prompt_password("Verfication: ")?;
    
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
                eprintln!("Error reading password: {:?}", e);
                return;
            },
            Ok(p) => p
        };
    
        let mut jots_file = jots::Jots::new(self.default_deriver, self.default_deriver_id);
    
        let file = match File::open(&file_in) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Error opening file. {:?}", e);
                return;                    
            }
        };
    
        let reader = BufReader::new(file);
        
        match jots_file.from_reader(reader) {
            Err(e) => {
                eprintln!("Error reading file. {:?}", e);
                return;                    
            },
            Ok(_) => ()                
        }
    
        match jots_file.to_enc_file(&file_out, &pw[..]) {
            Ok(_) => (),
            Err(e) => { 
                eprintln!("Error creating file. {:?}", e);
                return;
            },
        };
    }
    
    fn perform_decrypt_command(&mut self, decrypt_matches: &clap::ArgMatches) {
        self.set_pbkdf_from_command_line(decrypt_matches);
        let (file_in, file_out) = RustPwMan::determine_in_out_files(decrypt_matches);
        
        let mut jots_file = jots::Jots::new(self.default_deriver, self.default_deriver_id);
    
        let pw = match rpassword::prompt_password("Password: ") {
            Err(_) => { 
                eprintln!("Error reading password");
                return;
            },
            Ok(p) => p
        };
        
        match fcrypt::GcmContext::check_password(&pw) {
            Some(e) => {
                eprintln!("Password illegal: {:?}", e);
                return;
            },
            None => ()
        }    
        
        println!();
    
        match jots_file.from_enc_file(&file_in, &pw[..]) {
            Err(e) => {
                eprintln!("Error reading file. {:?}", e);
                return;                    
            },
            Ok(_) => ()
        };
    
        let file = match File::create(&file_out) {
            Err(e) => {
                eprintln!("Error creating file. {:?}", e);
                return;                    
            },
            Ok(f) => f      
        };
    
        let w = BufWriter::new(file);
    
        match jots_file.to_writer(w) {
            Err(e) => {
                eprintln!("Error writing file. {:?}", e);
                return;                    
            },
            Ok(_) => ()
        };
    }
    
    #[allow(unused_variables)]
    fn make_persist_creator(&self, u: &String, p: &String, s: &String, s_id: &String) -> PersistCreator {
        let persist_closure : PersistCreator;

        let u = u.clone();
        let p = p.clone();
        let s = s.clone();
        
        #[cfg(feature = "webdav")]
        {
            let test_str = format!("{}{}", s, s_id).to_lowercase();
            if test_str.starts_with("http") {
                persist_closure = Box::new(move |store_id: &String| -> Box<dyn Persister> {
                    return webdav::WebDavPersister::new(&u, &p, &s, store_id);
                });
            } else {
                persist_closure = Box::new(move |store_id: &String| -> Box<dyn Persister> {
                    return persist::FilePersister::new(store_id);
                });
            }
        }

        #[cfg(not(feature = "webdav"))]
        {
            persist_closure = Box::new(move |store_id: &String| -> Box<dyn Persister> {
                return persist::FilePersister::new(store_id);
            });
        }

        return persist_closure;
    }

    fn perform_gui_command(&mut self, gui_matches: &clap::ArgMatches) {
        self.set_pbkdf_from_command_line(gui_matches);
    
        let a:Option<&String> = gui_matches.get_one(ARG_INPUT_FILE);
        let u = self.webdav_user.clone();
        let mut p = self.webdav_pw.clone();
        let s = self.webdav_server.clone();

        match a {
            Some(v) => {
                let data_file_name : String = v.clone();

                if let Ok(_) = std::env::var(OBFUSCATION_ENV_VAR) {
                    p = match de_obfuscate(&p, OBFUSCATION_ENV_VAR) {
                        Some(s) => s,
                        None => {
                            eprintln!("Unable to de obfuscate password from config");
                            return;        
                        }
                    };
                }

                let persist_closure = self.make_persist_creator(&u, &p, &s, &data_file_name);

                modtui::tuimain::main(data_file_name, self.default_sec_level, self.default_deriver, self.default_deriver_id, 
                                      self.default_pw_gen, self.paste_command.clone(), self.copy_command.clone(), persist_closure);
            },
            None => {
                eprintln!("Password file name missing");
                return;
            }
        }
    }

    fn perform_obfuscate_command(&mut self) {
        let pw1 = rpassword::prompt_password("WebDAV password       : ").unwrap();
        let pw2 = rpassword::prompt_password("Again for verification: ").unwrap();
    
        if pw1 != pw2 {
            eprintln!("Passwords differ");
            return;
        }

        println!("{}", obfuscate(&pw1, OBFUSCATION_ENV_VAR));        
    }

    fn perform_config_command(&mut self, config_matches: &clap::ArgMatches) {
        let config_file_name: std::path::PathBuf;
        let a: Option<&String> = config_matches.get_one(ARG_CONFIG_FILE);

        match a {
            Some(f_name) => {
                config_file_name = std::path::PathBuf::from(f_name);
            },
            None => {
                config_file_name = match RustPwMan::get_cfg_file_name() {
                    Some(p) => p,
                    None => {
                        eprintln!("Unable to determine config file!");
                        return;
                    }
                };
            }
        }

        let mut file_was_loaded = false; 

        let loaded_config = match tomlconfig::load(&config_file_name, &mut file_was_loaded) {
            Ok(c) => c,
            Err(_) => {
                if file_was_loaded {
                    eprintln!("A config file was found but it seems to be corrupt!");
                    return;
                }

                tomlconfig::RustPwManSerialize {
                    seclevel: self.default_sec_level,
                    pbkdf: self.default_deriver_id.to_string(),
                    pwgen: self.default_pw_gen.to_string(),
                    clip_cmd: String::from(crate::modtui::DEFAULT_PASTE_CMD),
                    copy_cmd: String::from(crate::modtui::DEFAULT_COPY_CMD),
                    webdav_user: self.webdav_user.clone(),
                    webdav_pw: self.webdav_pw.clone(),
                    webdav_server: self.webdav_server.clone()
                }
            }
        };

        let sec_level = self.verify_sec_level(loaded_config.seclevel);
        let pw_gen_strategy = self.str_to_gen_strategy(&loaded_config.pwgen);
        let (_, pbkdf_id) = self.str_to_deriver(&loaded_config.pbkdf);

        tuiconfig::config_main(config_file_name, sec_level, pw_gen_strategy, pbkdf_id, &loaded_config.clip_cmd, &loaded_config.copy_cmd, 
                               &loaded_config.webdav_user, &loaded_config.webdav_pw, &loaded_config.webdav_server);
    }   

    fn perform_generate_command(&mut self) {
        tuigen::generate_main(self.default_sec_level, self.default_pw_gen);
    } 
}

pub fn add_kdf_param() -> clap::Arg {
    let mut arg = Arg::new(ARG_KDF);

    arg = arg.long(ARG_KDF);
    arg = arg.num_args(1);
    arg = arg.help("Use specific PBKDF");
    let ids: Vec<fcrypt::KdfId> = fcrypt::KdfId::get_known_ids();
    let mut possible_values: Vec<&str> = Vec::new();

    for i in ids {
        possible_values.push(i.to_str());
    }

    return arg.value_parser(possible_values);
}

fn main() {
    let mut app = Command::new("rustpwman")
        .version(VERSION_STRING)
        .author("Martin Grap <rmsk2@gmx.de>")
        .about("A password manager for the cursive TUI in Rust")          
        .subcommand(
            Command::new(COMMAND_ENCRYPT)
                .about("Encrypt file")        
                .arg(Arg::new(ARG_INPUT_FILE)
                    .short('i')
                    .long(ARG_INPUT_FILE)
                    .num_args(1)
                    .required(true)
                    .help("Name of plaintext file to encrypt"))
                .arg(Arg::new(ARG_OUTPUT_FILE)
                    .short('o')
                    .long(ARG_OUTPUT_FILE)
                    .required(true)
                    .num_args(1)
                    .help("Encrypted output file"))                    
                .arg(add_kdf_param()))
        .subcommand(
            Command::new(COMMAND_DECRYPT)
                .about("Decrypt file")        
                .arg(Arg::new(ARG_INPUT_FILE)
                    .short('i')
                    .long(ARG_INPUT_FILE)
                    .required(true)
                    .num_args(1)
                    .help("Name of encrypted file"))
                .arg(Arg::new(ARG_OUTPUT_FILE)
                    .short('o')
                    .long(ARG_OUTPUT_FILE)
                    .required(true)
                    .num_args(1)
                    .help("Name of plaintext file"))                    
                .arg(add_kdf_param()))
        .subcommand(
            Command::new(COMMAND_GUI)
                .about("Open file in TUI")        
                .arg(Arg::new(ARG_INPUT_FILE)
                    .short('i')
                    .long(ARG_INPUT_FILE)
                    .required(true)
                    .num_args(1)
                    .help("Name of encrypted data file"))                   
                .arg(add_kdf_param()))
        .subcommand(
            Command::new(COMMAND_CONFIG)
                .about("Change configuration")        
                .arg(Arg::new(ARG_CONFIG_FILE)
                    .short('c')
                    .long(ARG_CONFIG_FILE)
                    .num_args(1)
                    .help("Name of config file. Default is .rustpwman")))
        .subcommand(
            Command::new(COMMAND_GENERATE)
                .about("Generate passwords"))
        .subcommand(
            Command::new(COMMAND_OBFUSCATE)
                .about("Obfuscate WebDAV password")                
        );                    

    let mut rustpwman = RustPwMan::new();
    rustpwman.load_config();

    let matches = app.clone().get_matches();
    let subcommand = matches.subcommand();

    match subcommand {
        Some(m) => {
            match m {
                (COMMAND_ENCRYPT, encrypt_matches) => {
                    rustpwman.perform_encrypt_command(encrypt_matches);
                },
                (COMMAND_DECRYPT, decrypt_matches) => {
                    rustpwman.perform_decrypt_command(decrypt_matches);
                },
                (COMMAND_GUI, gui_matches) => {
                    rustpwman.perform_gui_command(gui_matches);
                },   
                (COMMAND_CONFIG, cfg_matches) => {
                    rustpwman.perform_config_command(cfg_matches);
                },
                (COMMAND_GENERATE, _) => {
                    rustpwman.perform_generate_command();
                },
                (COMMAND_OBFUSCATE, _) => {
                    rustpwman.perform_obfuscate_command();
                },                
                (&_, _) => panic!("Can not happen")           
            }
        },
        _ => {
            match app.print_long_help() {
                Err(e) => eprintln!("{}", e),
                _ => eprintln!("")
            }
        }        
    }
}