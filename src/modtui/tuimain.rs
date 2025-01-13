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


#[cfg(feature = "writebackup")]
use std::fs;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::sync::Arc;

use cursive::Cursive;
use cursive::views::Dialog;

use crate::fcrypt::KeyDeriver;
use crate::fcrypt;
use crate::jots::{self, CryptorGen};
use crate::pwgen::GenerationStrategy;
use super::AppState;
use super::open;
use crate::persist::SendSyncPersister;
use crate::persist;

use super::main_window;
use super::pwman_quit;
use super::pwentry;
#[cfg(feature = "pwmanclient")]
use super::cache;
use super::init;
use super::export;
#[cfg(feature = "writebackup")]
use crate::RustPwMan;


#[cfg(feature = "writebackup")]
pub fn write_backup_file(data: &Vec<u8>) -> std::io::Result<()> {
    let backup_file = match RustPwMan::get_backup_file_name() {
        None => {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Unable to determine path of backup file"))
        },
        Some(p) => p
    };

    return fs::write(backup_file, data);
}

pub fn main(data_file_name: String, default_sec_bits: usize, derive_func: KeyDeriver, deriver_id: fcrypt::KdfId, default_pw_gen: GenerationStrategy, 
            paste_cmd: String, copy_cmd: String, make_default: persist::PersistCreator, crypt_gen: Box<dyn Fn() -> CryptorGen + Send + Sync>, export: bool) {
    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    let capture_file_name = data_file_name.clone();
    let mut siv = cursive::default();
    let sender = Arc::new(tx);
    let sender_main = sender.clone();

    let p = make_default(&data_file_name);    

    // stuff to run after successfull password entry
    let pw_callback = Box::new(move |s: &mut Cursive, password: &String, pw_cached: bool| {
        let p_cb = make_default(&capture_file_name);
        let mut jots_store = jots::Jots::new(derive_func, deriver_id, crypt_gen());
        
        #[cfg(feature = "writebackup")]
        {
            jots_store.backup_cb = Some(write_backup_file);
        }

        #[cfg(not(feature = "writebackup"))]
        {
            jots_store.backup_cb = None;
        }        
        
        let f_name = capture_file_name.clone();

        let state = AppState::new(jots_store, &f_name, default_sec_bits, default_pw_gen, &paste_cmd, &copy_cmd, p_cb, pw_cached);

        // No else branch is neccessary as open_file performs error handling
        if let Some(state_after_open) = open::storage(s, password, state) {
            s.pop_layer(); // Close password, file init or confirmation dialog
            if !export {
                main_window(s, state_after_open, sender_main.clone());
            } else {
                export::window(s, state_after_open, sender_main.clone());
            }            
        }
    });

    if !export {
        // Add a layer for the password entry dialog
        #[cfg(feature = "pwmanclient")]
        setup_password_entry_with_pwman(&mut siv, sender, pw_callback, &p);

        #[cfg(not(feature = "pwmanclient"))]
        setup_password_entry_without_pwman(&mut siv, sender, pw_callback, &p);
    } else {
        // force user to enter the password
        setup_password_entry_without_pwman(&mut siv, sender, pw_callback, &p);
    }

    // run password entry dialog
    siv.run();

    let message = match rx.recv() {
        Ok(s) => s,
        Err(_) => String::from("Unable to receive message")
    };

    if message != "" {
        println!("{}", message);
    }
    
}

fn show_unable_to_check_error(siv: &mut Cursive, msg: &str, sender: Arc<Sender<String>>) {
    siv.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Ok", move |s| {
                s.pop_layer();
                pwman_quit(s, sender.clone(), String::from(""))
            }),
    );    
}

#[cfg(feature = "pwmanclient")]
fn setup_password_entry_with_pwman(siv: &mut Cursive, sender: Arc<Sender<String>>, pw_callback: Box<dyn Fn(&mut Cursive, &String, bool) + Send + Sync>, p: &SendSyncPersister) {
    let does_exist = match p.does_exist() {
        Ok(b) => b,
        Err(_) => {
            show_unable_to_check_error(siv, "Unable to determine if password storage exists. Quitting now ...", sender.clone());
            return;
        }
    };

    if does_exist {
        let store_id = match p.get_canonical_path() {
            Ok(s) => s,
            Err(_) => {
                show_unable_to_check_error(siv, "Unable to determine canonical storage identity. Quitting now ...", sender.clone());    
                return 
            }
        };        

        match cache::make_pwman_client(store_id) {
            Ok(c) => {
                match c.get_password() {
                    Ok(password) => {
                        let d = cache::confirmation_dialog(sender.clone(), password.clone(), c, pw_callback);
                        siv.add_layer(d);
                    },
                    Err(_) => {                        
                        let d = pwentry::dialog(sender.clone(), pw_callback);
                        siv.add_layer(d);        
                    }
                }
            }
            Err(_) => {                
                let d = pwentry::dialog(sender.clone(), pw_callback);
                siv.add_layer(d);
            }
        };
    } else {
        let d = init::dialog(sender.clone(), pw_callback);
        siv.add_layer(d);
    }
}

fn setup_password_entry_without_pwman(siv: &mut Cursive, sender: Arc<Sender<String>>, pw_callback: Box<dyn Fn(&mut Cursive, &String, bool) + Send + Sync>, p: &SendSyncPersister) {
    let does_exist = match p.does_exist() {
        Ok(b) => b,
        Err(_) => {
            show_unable_to_check_error(siv, "Unable to determine canonical storage identity. Quitting now ...", sender.clone());
            return;
        }
    };

    if does_exist {
        let d = pwentry::dialog(sender.clone(), pw_callback);
        siv.add_layer(d);
    } else {
        let d = init::dialog(sender.clone(), pw_callback);
        siv.add_layer(d);
    }
}