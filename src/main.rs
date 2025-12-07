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

#[cfg(test)]
mod tests;
mod fcrypt;
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
const RUSTPWMAN_VIEWER: &str = "RUSTPWMAN_VIEWER";
const PWMAN_CONFIG: &str = "PWMAN_CONFIG";

use std::env;
use std::fmt;
use std::path::PathBuf;
use dirs;
use clap::{Arg, Command, ArgAction};
use fcrypt::CipherId;
use modtui::DEFAULT_PASTE_CMD;
use modtui::DEFAULT_COPY_CMD;
use persist::PersistCreator;
use persist::SendSyncPersister;
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
const ARG_CIPHER: &str = "cipher";
const ARG_EXPORT: &str = "backup";
#[cfg(not(feature = "chacha20"))]
const SINGLE_CIPHER_DEFAULT: CipherId = CipherId::Aes256Gcm;
#[cfg(feature = "chacha20")]
const MULTIPLE_CIPHER_DEFAULT_ENV_NOT_SET: CipherId = CipherId::Aes256Gcm;
#[cfg(feature = "chacha20")]
const MULTIPLE_CIPHER_DEFAULT_ENV_SET: CipherId = CipherId::ChaCha20Poly1305;
pub const CFG_FILE_NAME: &str = ".rustpwman";
pub const BACKUP_FILE_NAME: &str = "rustpwman_last.enc";
pub const ENV_CIPHER: &str = "PWMANCIPHER";
pub const ENV_BKP: &str = "PWMANBKP";

use fcrypt::DEFAULT_KDF_ID;

use crate::fcrypt::KdfId;

#[derive(Clone)]
pub struct InfoParams {
    cfg_source: CfgSource,
    cfg_name: String,
    kdf_id: KdfId
}

struct RustPwMan {
    default_deriver: fcrypt::KeyDeriver,
    default_deriver_id: fcrypt::KdfId,
    default_sec_level: usize,
    default_pw_gen: GenerationStrategy,
    paste_command: String,
    copy_command: String,
    viewer_command: Option<String>,
    bkp_file_name: Option<String>,
    webdav_user: String,
    webdav_pw: String,
    webdav_server: String,
    info: Option<InfoParams>
}

enum CfgFailReaction {
    Reset,
    Abort
}
#[derive(PartialEq)]
#[derive(Debug, Copy, Clone)]
enum CfgSource {
    Environment,
    CLI,
    Default,
    Nothing
}

impl fmt::Display for CfgSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[allow(unused_variables)]
pub fn make_cryptor(id: &str, d: fcrypt::KeyDeriver, i: fcrypt::KdfId) -> Box<dyn fcrypt::Cryptor> {
    #[cfg(not(feature = "chacha20"))]
    return SINGLE_CIPHER_DEFAULT.make(d, i);

    #[cfg(feature = "chacha20")]
    {
        let mut algo_id = String::from(id);

        if algo_id == "" {
            algo_id = match env::var(ENV_CIPHER) {
                Ok(s) => String::from(s.as_str()),
                Err(_) => String::from(MULTIPLE_CIPHER_DEFAULT_ENV_NOT_SET.to_str())
            }
        }

        algo_id = algo_id.to_lowercase();

        if let Some(cip_id) = CipherId::from_str(algo_id.as_str()) {
            return cip_id.make(d, i);
        } else {
            return MULTIPLE_CIPHER_DEFAULT_ENV_SET.make(d, i);
        }
    }
}

impl RustPwMan {
    fn new() -> Self {
        let (default_kdf, _) = DEFAULT_KDF_ID.to_named_func();

        let mut res = RustPwMan {
            default_deriver: default_kdf,
            default_deriver_id: DEFAULT_KDF_ID,
            default_sec_level: modtui::PW_SEC_LEVEL,
            default_pw_gen: GenerationStrategy::Base64,
            paste_command: String::from(DEFAULT_PASTE_CMD),
            copy_command: String::from(DEFAULT_COPY_CMD),
            bkp_file_name: RustPwMan::get_bkp_file_name_from_env(),
            viewer_command: RustPwMan::get_viewer_from_env(),
            webdav_user: String::new(),
            webdav_pw: String::new(),
            webdav_server: String::new(),
            info: None
        };

        res.reset_config();
        return res;
    }

    fn reset_config(&mut self) {
        let (default_kdf, _) = DEFAULT_KDF_ID.to_named_func();

        self.default_deriver = default_kdf;
        self.default_deriver_id = DEFAULT_KDF_ID;
        self.default_sec_level = modtui::PW_SEC_LEVEL;
        self.default_pw_gen = GenerationStrategy::Base64;
        self.paste_command = String::from(DEFAULT_PASTE_CMD);
        self.copy_command = String::from(DEFAULT_COPY_CMD);
        self.viewer_command = RustPwMan::get_viewer_from_env();
        self.bkp_file_name = RustPwMan::get_bkp_file_name_from_env();
        self.webdav_user = String::from("");
        self.webdav_pw = String::from("");
        self.webdav_server = String::from("");
        self.info = None;
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

    fn get_info(&self) -> Option<InfoParams> {
        return self.info.clone();
    }

    fn get_viewer_from_env() -> Option<String> {
        let viewer = match env::var(RUSTPWMAN_VIEWER) {
            Ok(s) => {
                let temp = s.clone();
                Some(temp)
            },
            Err(_) => None
        };

        return viewer;
    }
    
    fn get_bkp_file_name_from_env() -> Option<String> {
        #[cfg(not(feature = "writebackup"))]
        return None;

        #[cfg(feature = "writebackup")]
        return match env::var(ENV_BKP) {
            Ok(s) => Some(String::from(s.as_str())),
            Err(_) => Some(String::from(BACKUP_FILE_NAME))            
        };
    }

    pub fn get_backup_file_name_str(&self) -> Option<String> {
        return self.bkp_file_name.clone();
    }

    #[allow(dead_code)]
    pub fn get_backup_file_name(&self) -> std::path::PathBuf {
        let mut path = std::path::PathBuf::new();
        path.push(self.bkp_file_name.clone().unwrap());

        return path;
    }

    fn load_named_config(&mut self, cfg_file: &PathBuf, fail_reaction: CfgFailReaction, source: CfgSource) -> Option<String>{
        let mut file_was_read = false;

        if let Ok(loaded_config) = tomlconfig::load(&cfg_file, &mut file_was_read) {
            let (k, id) = self.str_to_deriver(&loaded_config.pbkdf[..]);

            self.default_deriver = k;
            self.default_deriver_id = id;
            self.default_pw_gen = self.str_to_gen_strategy(&loaded_config.pwgen[..]);
            self.default_sec_level = self.verify_sec_level(loaded_config.seclevel);
            self.paste_command = loaded_config.clip_cmd;
            self.copy_command = loaded_config.copy_cmd;

            // If the config contains a viewer command prefix use this instead of the value
            // read from the environment.
            if loaded_config.viewer_cmd != None {
                self.viewer_command = loaded_config.viewer_cmd;
            }

            // If the config contains a backup file name use this instead of the value
            // read from the environment.            
            if loaded_config.bkp_file_name != None {
                self.bkp_file_name = loaded_config.bkp_file_name;
            }

            self.webdav_user = loaded_config.webdav_user;
            self.webdav_pw = loaded_config.webdav_pw;
            self.webdav_server = loaded_config.webdav_server;

            return None;
        } else {
            if file_was_read {
                return Some(String::from("A config file was found but it seems to be corrupt!"));
            } else {
                match fail_reaction {
                    CfgFailReaction::Abort => {
                        if source != CfgSource::Default {
                            let error_message = match cfg_file.as_os_str().to_str() {
                                Some(s) => format!("Config file '{}' as specified through the '{}' was not found!", s, source),
                                None => String::from("Config file not fount and could not convert the file name to UTF-8")
                            };
                            return Some(error_message);
                        } else {
                            // We do not abort when the user has not specified a dedicated config file through the CLI or the
                            // environment and the default config file does not exist (yet).
                            self.reset_config();
                            return None;                            
                        }                        
                    },
                    CfgFailReaction::Reset => {
                        self.reset_config();
                        return None;
                    }
                }
            }
        }
    }

    fn get_config_name(&mut self, config_matches: &clap::ArgMatches) -> (CfgSource, Option<PathBuf>) {
        let a: Option<&String> = config_matches.get_one(ARG_CONFIG_FILE);

        match a {
            Some(f_name) => {
                // cfgfile was specified on command line
                return (CfgSource::CLI, Some(PathBuf::from(f_name)));
            },
            None => {
                if let Ok(file_name) = env::var(PWMAN_CONFIG) {
                    // PWMAN_CONFIG was set
                    return (CfgSource::Environment, Some(PathBuf::from(file_name)));
                }

                // Use .rustpwman in user's home directory
                let mut home_dir = match dirs::home_dir() {
                    Some(p) => p,
                    None => return (CfgSource::Nothing, None)
                };

                home_dir.push(CFG_FILE_NAME);

                return (CfgSource::Default, Some(home_dir));
            }
        }
    }

    fn load_config(&mut self, matches: &clap::ArgMatches, fail_reaction: CfgFailReaction) -> (CfgSource, PathBuf, Option<String>) {
        let config_file_name: std::path::PathBuf;
        let (cfg_type, file_path) = self.get_config_name(matches);

        match file_path {
            Some(f_name) => {
                config_file_name = std::path::PathBuf::from(f_name);
            },
            None => {
                return (CfgSource::Default, PathBuf::new(), Some(String::from("Unable to determine config file!")));
            }
        };

        let h = config_file_name.clone();
        return (cfg_type, config_file_name, self.load_named_config(&h, fail_reaction, cfg_type));
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

        match fcrypt::check_password(&pw1) {
            Some(e) => return Err(e),
            None => ()
        }

        return Ok(pw1);
    }

    fn perform_encrypt_command(&mut self, encrypt_matches: &clap::ArgMatches) {
        if let (_, _, Some(error_message)) = self.load_config(encrypt_matches, CfgFailReaction::Abort)  {
            eprintln!("{}", error_message.as_str());
            return;
        }

        self.set_pbkdf_from_command_line(encrypt_matches);
        let (file_in, file_out) = RustPwMan::determine_in_out_files(encrypt_matches);

        let pw = match RustPwMan::enter_password_verified() {
            Err(e) => {
                eprintln!("Error reading password: {:?}", e);
                return;
            },
            Ok(p) => p
        };

        let a: Option<&String> = encrypt_matches.get_one(ARG_CIPHER);
        let algo_id = match a {
            Some(s) => String::from(s.as_str()),
            None => String::from("")
        };

        let cr_gen = Box::new(move |k: fcrypt::KeyDeriver, i: fcrypt::KdfId| -> Box<dyn fcrypt::Cryptor>  {
            return make_cryptor(algo_id.as_str(), k, i);
        });

        let mut jots_file = jots::Jots::new(self.default_deriver, self.default_deriver_id, cr_gen);

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
        if let (_, _, Some(error_message)) = self.load_config(decrypt_matches, CfgFailReaction::Abort)  {
            eprintln!("{}", error_message.as_str());
            return;
        }

        self.set_pbkdf_from_command_line(decrypt_matches);
        let (file_in, file_out) = RustPwMan::determine_in_out_files(decrypt_matches);

        let a: Option<&String> = decrypt_matches.get_one(ARG_CIPHER);
        let algo_id = match a {
            Some(s) => String::from(s.as_str()),
            None => String::from("")
        };

        let cr_gen = Box::new(move |k: fcrypt::KeyDeriver, i: fcrypt::KdfId| -> Box<dyn fcrypt::Cryptor>  {
            return make_cryptor(algo_id.as_str(), k, i);
        });

        let mut jots_file = jots::Jots::new(self.default_deriver, self.default_deriver_id, cr_gen);

        let pw = match rpassword::prompt_password("Password: ") {
            Err(_) => {
                eprintln!("Error reading password");
                return;
            },
            Ok(p) => p
        };

        match fcrypt::check_password(&pw) {
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
                persist_closure = Box::new(move |store_id: &String| -> SendSyncPersister {
                    return webdav::WebDavPersister::new(&u, &p, &s, store_id);
                });
            } else {
                persist_closure = Box::new(move |store_id: &String| -> SendSyncPersister {
                    return persist::FilePersister::new(store_id);
                });
            }
        }

        #[cfg(not(feature = "webdav"))]
        {
            persist_closure = Box::new(move |store_id: &String| -> SendSyncPersister {
                return persist::FilePersister::new(store_id);
            });
        }

        return persist_closure;
    }

    fn perform_gui_command(&mut self, gui_matches: &clap::ArgMatches) {
        let (cfg_type, cfg_file ,error_msg) = self.load_config(gui_matches, CfgFailReaction::Abort);

        if  let Some(error_message) = error_msg {
            eprintln!("{}", error_message.as_str());
            return;
        }

        self.set_pbkdf_from_command_line(gui_matches);

        self.info = Some(InfoParams {
            cfg_source: cfg_type,
            cfg_name: match cfg_file.as_os_str().to_str() {
                None => String::from("Can not convert name of config file to UTF-8"),
                Some(str) => String::from(str)
            },
            kdf_id: self.default_deriver_id
        });

        let a:Option<&String> = gui_matches.get_one(ARG_INPUT_FILE);
        let u = self.webdav_user.clone();
        let mut p = self.webdav_pw.clone();
        let s = self.webdav_server.clone();

        let cip: Option<&String> = gui_matches.get_one(ARG_CIPHER);
        let algo_id = match cip {
            Some(s) => String::from(s.as_str()),
            None => String::from("")
        };

        let cr_gen_gen = Box::new(move || -> jots::CryptorGen {
            let h = algo_id.clone();
            return Box::new(move |k: fcrypt::KeyDeriver, i: fcrypt::KdfId| -> Box<dyn fcrypt::Cryptor>  {
                return make_cryptor(h.as_str(), k, i);
            });
        });

        match a {
            Some(v) => {
                let data_file_name : String = v.clone();

                if obfuscate::is_obfuscation_possible(OBFUSCATION_ENV_VAR) {
                    p = match de_obfuscate(&p, OBFUSCATION_ENV_VAR) {
                        Some(s) => s,
                        None => {
                            eprintln!("Unable to de obfuscate password from config");
                            return;
                        }
                    };
                }

                let persist_closure = self.make_persist_creator(&u, &p, &s, &data_file_name);

                modtui::tuimain::main(self, data_file_name, self.default_sec_level, self.default_deriver, self.default_deriver_id,
                                      self.default_pw_gen, self.paste_command.clone(), self.copy_command.clone(), persist_closure, cr_gen_gen, gui_matches.get_flag(ARG_EXPORT), self.viewer_command.clone());
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
        let (_, config_file_name, err_msg) = self.load_config(config_matches, CfgFailReaction::Reset);

        if let Some(error_message) = err_msg  {
            eprintln!("{}", error_message.as_str());
            return;
        }

        let mut viewer_cmd = RustPwMan::get_viewer_from_env();
        if self.viewer_command != None {
            viewer_cmd = self.viewer_command.clone();
        }

        tuiconfig::config_main(self, config_file_name, self.default_sec_level, self.default_pw_gen, self.default_deriver_id, &self.paste_command, &self.copy_command, &self.webdav_user, &self.webdav_pw, &self.webdav_server, &viewer_cmd);
    }

    fn perform_generate_command(&mut self, generate_matches: &clap::ArgMatches) {
        if let (_, _, Some(error_message)) = self.load_config(generate_matches, CfgFailReaction::Abort)  {
            eprintln!("{}", error_message.as_str());
            return;
        }

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

pub fn add_cipher_param() -> clap::Arg {
    let arg = Arg::new(ARG_CIPHER)
        .long(ARG_CIPHER)
        .short('c')
        .required(false)
        .num_args(1)
        .help("Use specific cipher");

    let ids: Vec<fcrypt::CipherId> = fcrypt::CipherId::get_known_ids();
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
                .arg(Arg::new(ARG_CONFIG_FILE)
                    .long(ARG_CONFIG_FILE)
                    .num_args(1)
                    .help("Name of config file. Default is .rustpwman"))
                .arg(add_kdf_param())
                .arg(add_cipher_param()))
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
                .arg(Arg::new(ARG_CONFIG_FILE)
                    .long(ARG_CONFIG_FILE)
                    .num_args(1)
                    .help("Name of config file. Default is .rustpwman"))
                .arg(add_kdf_param())
                .arg(add_cipher_param()))
        .subcommand(
            Command::new(COMMAND_GUI)
                .about("Open file in TUI")
                .arg(Arg::new(ARG_INPUT_FILE)
                    .short('i')
                    .long(ARG_INPUT_FILE)
                    .required(true)
                    .num_args(1)
                    .help("Name of encrypted data file"))
                .arg(add_kdf_param())
                .arg(add_cipher_param())
                .arg(Arg::new(ARG_EXPORT)
                    .long(ARG_EXPORT)
                    .required(false)
                    .action(ArgAction::SetTrue)
                    .help("Allow to create a plaintext backup during startup"))
                .arg(Arg::new(ARG_CONFIG_FILE)
                    .long(ARG_CONFIG_FILE)
                    .num_args(1)
                    .help("Name of config file. Default is .rustpwman")))
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
                .about("Generate passwords")
                .arg(Arg::new(ARG_CONFIG_FILE)
                    .short('c')
                    .long(ARG_CONFIG_FILE)
                    .num_args(1)
                    .help("Name of config file. Default is .rustpwman")))
        .subcommand(
            Command::new(COMMAND_OBFUSCATE)
                .about("Obfuscate WebDAV password")
        );

    let mut rustpwman = RustPwMan::new();

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
                (COMMAND_GENERATE, generate_matches) => {
                    rustpwman.perform_generate_command(generate_matches);
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
