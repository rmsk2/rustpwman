use std::rc::Rc;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::collections::HashMap;

use cursive::Cursive;
use cursive::views::Dialog;

use crate::pwgen;
use crate::fcrypt::KeyDeriver;
use crate::fcrypt;
use crate::jots;
use crate::pwgen::GenerationStrategy;
use crate::pwgen::PasswordGenerator;
use super::AppState;
use super::open;
use crate::persist::Persister;

use super::main_window;
use super::pwman_quit;
use super::pwentry;
#[cfg(feature = "pwmanclient")]
use super::cache;
use super::init;

pub fn main(data_file_name: String, default_sec_bits: usize, derive_func: KeyDeriver, deriver_id: fcrypt::KdfId, default_pw_gen: GenerationStrategy, paste_cmd: String, copy_cmd: String) {
    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    let capture_file_name = data_file_name.clone();
    let mut siv = cursive::default();
    let sender = Rc::new(tx);
    let sender_main = sender.clone();

    // stuff to run after successfull password entry
    let pw_callback = Box::new(move |s: &mut Cursive, password: &String| {
        let jots_store = jots::Jots::new(derive_func, deriver_id);
        let f_name = capture_file_name.clone();
        let mut generators: HashMap<GenerationStrategy, Box<dyn PasswordGenerator>> = HashMap::new();

        for i in pwgen::GenerationStrategy::get_known_ids() {
            generators.insert(i, i.to_creator()());
        }

        let state = AppState::new(jots_store, &f_name, generators, default_sec_bits, default_pw_gen, &paste_cmd, &copy_cmd);

        // No else branch is neccessary as open_file performs error handling
        if let Some(state_after_open) = open::storage(s, password, state) {
            s.pop_layer(); // Close password, file init or confirmation dialog
            main_window(s, state_after_open, sender_main.clone());
        }
    });

    // Add a layer for the password entry dialog
    #[cfg(feature = "pwmanclient")]
    setup_password_entry_with_pwman(&mut siv, &data_file_name, sender, pw_callback, &AppState::make_persister(&data_file_name));

    #[cfg(not(feature = "pwmanclient"))]
    setup_password_entry_without_pwman(&mut siv, &data_file_name, sender, pw_callback, &AppState::make_persister(&data_file_name));

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

fn show_unable_to_check_error(siv: &mut Cursive, sender: Rc<Sender<String>>) {
    siv.add_layer(
        Dialog::text("Unable to determine if password storage exists. Quitting now ...")
            .title("Rustpwman")
            .button("Ok", move |s| {
                s.pop_layer();
                pwman_quit(s, sender.clone(), String::from(""))
            }),
    );    
}

#[cfg(feature = "pwmanclient")]
fn setup_password_entry_with_pwman(siv: &mut Cursive, store_id: &String, sender: Rc<Sender<String>>, pw_callback: Box<dyn Fn(&mut Cursive, &String)>, p: &Box<dyn Persister>) {
    let does_exist = match p.does_exist() {
        Ok(b) => b,
        Err(_) => {
            show_unable_to_check_error(siv, sender.clone());
            return;
        }
    };

    if does_exist {
        let store_id_for_uds_client = store_id.clone();

        match cache::make_pwman_client(store_id_for_uds_client.clone()) {
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


#[cfg(not(feature = "pwmanclient"))]
fn setup_password_entry_without_pwman(siv: &mut Cursive, _store_id: &String, sender: Rc<Sender<String>>, pw_callback: Box<dyn Fn(&mut Cursive, &String)>, p: &Box<dyn Persister>) {
    let does_exist = match p.does_exist() {
        Ok(b) => b,
        Err(_) => {
            show_unable_to_check_error(siv, sender.clone());
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