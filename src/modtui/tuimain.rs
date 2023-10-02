use std::rc::Rc;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::collections::HashMap;

use cursive::Cursive;

use crate::pwgen;
use crate::fcrypt::KeyDeriver;
use crate::fcrypt;
use crate::jots;
use crate::pwgen::GenerationStrategy;
use crate::pwgen::PasswordGenerator;
use super::AppState;

use super::main_window;
use super::path_exists;
use super::pwentry;
#[cfg(feature = "pwmanclient")]
use super::cache;
use super::init;

pub fn main(data_file_name: String, default_sec_bits: usize, derive_func: KeyDeriver, deriver_id: fcrypt::KdfId, default_pw_gen: GenerationStrategy, paste_cmd: String) {
    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    let capture_file_name = data_file_name.clone();
    let mut siv = cursive::default();
    let sender = Rc::new(tx);
    let sender_main = sender.clone();

    let pw_callback = Box::new(move |s: &mut Cursive, password: &String| {
        let jots_store = jots::Jots::new(derive_func, deriver_id);
        let f_name = capture_file_name.clone();
        let mut generators: HashMap<GenerationStrategy, Box<dyn PasswordGenerator>> = HashMap::new();

        for i in pwgen::GenerationStrategy::get_known_ids() {
            generators.insert(i, i.to_creator()());
        }

        let state = AppState::new(jots_store, &f_name, generators, default_sec_bits, default_pw_gen, &paste_cmd);

        if let Some(state_after_open) = pwentry::open_file(s, password, state) {
            s.pop_layer(); // Close password, file init or confirmation dialog
            main_window(s, state_after_open, sender_main.clone());
        }
    });

    #[cfg(feature = "pwmanclient")]
    handle_password_entry_with_pwman(&mut siv, &data_file_name, sender, pw_callback);

    #[cfg(not(feature = "pwmanclient"))]
    handle_password_entry_without_pwman(&mut siv, &data_file_name, sender, pw_callback);

    siv.run();

    let message = match rx.recv() {
        Ok(s) => s,
        Err(_) => String::from("Unable to receive message")
    };

    if message != "" {
        println!("{}", message);
    }
    
}

#[cfg(feature = "pwmanclient")]
fn handle_password_entry_with_pwman(siv: &mut Cursive, data_file_name: &String, sender: Rc<Sender<String>>, pw_callback: Box<dyn Fn(&mut Cursive, &String)>) {
    if path_exists(&data_file_name) {
        let file_name_for_uds_client = data_file_name.clone();

        match cache::make_pwman_client(file_name_for_uds_client.clone()) {
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
fn handle_password_entry_without_pwman(siv: &mut Cursive, data_file_name: &String, sender: Rc<Sender<String>>, pw_callback: Box<dyn Fn(&mut Cursive, &String)>) {
    if path_exists(&data_file_name) {
        let d = pwentry::dialog(sender.clone(), pw_callback);
        siv.add_layer(d);
    } else {
        let d = init::dialog(sender.clone(), pw_callback);
        siv.add_layer(d);
    }
}