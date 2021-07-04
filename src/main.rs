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
use rpassword;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};

pub const VERSION_STRING: &str = "0.5.6";
const COMMAND_ENCRYPT: &str = "enc";
const COMMAND_DECRYPT: &str = "dec";
const COMMAND_GUI: &str = "gui";
const ARG_INPUT_FILE: &str = "inputfile";
const ARG_OUTPUT_FILE: &str = "outputfile";
const ARG_SCRYPT: &str = "scrypt";

fn determine_pbkdf(matches: &clap::ArgMatches) -> fcrypt::KeyDeriver {
    let mut derive: fcrypt::KeyDeriver = fcrypt::GcmContext::sha256_deriver;

    if matches.is_present(ARG_SCRYPT) {
        derive = fcrypt::GcmContext::scrypt_deriver;
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

    return Ok(pw1);
}

fn perform_encrypt_command(encrypt_matches: &clap::ArgMatches) {
    let derive: fcrypt::KeyDeriver = determine_pbkdf(encrypt_matches);
    let (file_in, file_out) = determine_in_out_files(encrypt_matches);
    
    let pw = match enter_password_verified() {
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

fn perform_decrypt_command(decrypt_matches: &clap::ArgMatches) {
    let derive: fcrypt::KeyDeriver = determine_pbkdf(decrypt_matches);
    let (file_in, file_out) = determine_in_out_files(decrypt_matches);
    
    let mut jots_file = jots::Jots::new(derive);

    let pw = match rpassword::read_password_from_tty(Some("Password: ")) {
        Err(_) => { 
            println!("Error reading password");
            return;
        },
        Ok(p) => p
    };
    
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

fn perform_gui_command(gui_matches: &clap::ArgMatches) {
    let derive: fcrypt::KeyDeriver = determine_pbkdf(gui_matches);

    let mut file_names: Vec<String> = Vec::new();
    if let Some(in_files) = gui_matches.values_of(ARG_INPUT_FILE) {
        in_files.for_each(|x| file_names.push(String::from(x)));
    }

    let data_file_name = file_names[0].clone();
    let default_sec_bits = modtui::AppState::determine_sec_level();

    modtui::main_gui(data_file_name, default_sec_bits, derive);
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
        (COMMAND_ENCRYPT, Some(encrypt_matches)) => {
            perform_encrypt_command(encrypt_matches);
        },
        (COMMAND_DECRYPT, Some(decrypt_matches)) => {
            perform_decrypt_command(decrypt_matches);
        },
        (COMMAND_GUI, Some(gui_matches)) => {
            perform_gui_command(gui_matches);
        },        
        _ => {
            match app.print_long_help() {
                Err(e) => eprintln!("{}", e),
                _ => eprintln!("")
            }
        }
    };
}