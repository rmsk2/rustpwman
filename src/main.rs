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

use clap::{Arg, App, SubCommand};

const COMMAND_ENCRYPT: &str = "enc";
const COMMAND_DECRYPT: &str = "dec";
const COMMAND_GUI: &str = "gui";
const ARG_INPUT_FILE: &str = "inputfile";
const ARG_OUTPUT_FILE: &str = "outputfile";
const ARG_SCRYPT: &str = "scrypt";

fn main() {
    let mut app = App::new("rustpwman")
        .version("0.5.5")
        .author("Martin Grap <rmsk2@gmx.de>")
        .about("A password manager for the cursive TUI in Rust")          
        .subcommand(
            SubCommand::with_name(COMMAND_ENCRYPT)
                .about("Encrypt file")        
                .arg(Arg::with_name(ARG_INPUT_FILE)
                    .short("i")
                    .long("input")
                    .takes_value(true)
                    .required(true)
                    .help("Name of plaintext file to encrypt"))
                .arg(Arg::with_name(ARG_OUTPUT_FILE)
                    .short("o")
                    .long("output")
                    .required(true)
                    .takes_value(true)
                    .help("Encrypted output file"))                    
                .arg(Arg::with_name(ARG_SCRYPT)
                    .long("scrypt")
                    .help("Use Scrypt as PBKDF")))
        .subcommand(
            SubCommand::with_name(COMMAND_DECRYPT)
                .about("Decrypt file")        
                .arg(Arg::with_name(ARG_INPUT_FILE)
                    .short("i")
                    .long("input")
                    .required(true)
                    .takes_value(true)
                    .help("Name of encrypted file"))
                .arg(Arg::with_name(ARG_OUTPUT_FILE)
                    .short("o")
                    .long("output")
                    .required(true)
                    .takes_value(true)
                    .help("Name of plaintext file"))                    
                .arg(Arg::with_name(ARG_SCRYPT)
                    .long("scrypt")
                    .help("Use Scrypt as PBKDF")))
        .subcommand(
            SubCommand::with_name(COMMAND_GUI)
                .about("Open file in TUI")        
                .arg(Arg::with_name(ARG_INPUT_FILE)
                    .short("i")
                    .long("input")
                    .required(true)
                    .takes_value(true)
                    .help("Name of encrypted data file"))                   
                .arg(Arg::with_name(ARG_SCRYPT)
                    .long("scrypt")
                    .help("Use Scrypt as PBKDF")));                    

    let matches = app.clone().get_matches();
    let subcommand = matches.subcommand();

    match subcommand {
        (COMMAND_ENCRYPT, Some(_encrypt_matches)) => {
            ()
        },
        (COMMAND_DECRYPT, Some(_decrypt_matches)) => {
            ()
        },
        (COMMAND_GUI, Some(gui_matches)) => {
            let mut derive: fcrypt::KeyDeriver = fcrypt::GcmContext::sha256_deriver;

            if gui_matches.is_present(ARG_SCRYPT) {
                derive = fcrypt::GcmContext::scrypt_deriver;
            }

            let mut file_names: Vec<String> = Vec::new();
            if let Some(in_files) = gui_matches.values_of(ARG_INPUT_FILE) {
                in_files.for_each(|x| file_names.push(String::from(x)));
            }

            let data_file_name = file_names[0].clone();
            let default_sec_bits = modtui::AppState::determine_sec_level();
        
            modtui::main_gui(data_file_name, default_sec_bits, derive);
        },        
        _ => {
            match app.print_long_help() {
                Err(e) => eprintln!("{}", e),
                _ => eprintln!("")
            }
        }
    };
}