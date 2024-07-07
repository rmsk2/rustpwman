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


use std::sync::{Arc, Mutex};
#[cfg(feature = "pwmanclient")]
use std::sync::mpsc::Sender;


use super::AppState;
use super::show_message;
#[cfg(feature = "pwmanclient")]
use super::pwman_quit;
#[cfg(feature = "pwmanclientux")]
use crate::pwman_client_ux::UDSClient;
#[cfg(feature = "pwmanclientwin")]
use crate::pwman_client_win::UDSClientWin;
#[cfg(feature = "pwmanclient")]
use crate::pwman_client::PWManClient;

use cursive::Cursive;
#[cfg(feature = "pwmanclient")]
use cursive::views::{Dialog, LinearLayout, TextView};

#[cfg(feature = "pwmanclientux")]
pub fn make_pwman_client(file_name: String) -> std::io::Result<Box<dyn PWManClient + Send + Sync>>{
    match UDSClient::new(file_name) {
        Ok(c) => return Ok(Box::new(c)),
        Err(e) => return Err(e)
    }
}

#[cfg(feature = "pwmanclientwin")]
pub fn make_pwman_client(file_name: String) -> std::io::Result<Box<dyn PWManClient>>{
    match UDSClientWin::new(file_name) {
        Ok(c) => return Ok(Box::new(c)),
        Err(e) => return Err(e)
    }
}

#[cfg(feature = "pwmanclient")]
pub fn password(s: &mut Cursive, state_for_write_cache: Arc<Mutex<AppState>>) {
    let pw_option = state_for_write_cache.lock().unwrap().password.clone();
    let file_name = match state_for_write_cache.lock().unwrap().persister.get_canonical_path() {
        Ok(s) => s,
        Err(_) => {
            show_message(s, "Unable to determine canonical storage identity");    
            return 
        }
    };

    let password : String;
    let client: Box<dyn PWManClient>;

    if let Some(p) = pw_option {
        password = p;
    } else {
        show_message(s, "No password found in application state");
        return;
    }

    let c = make_pwman_client(file_name);
    if let Ok(cl) = c {
        client = cl;
    } else {
        show_message(s, "Unable to construct PWMAN client");
        return;
    }

    match client.set_password(&password) {
        Ok(_) => {
            state_for_write_cache.lock().unwrap().pw_is_chached = true;
            show_message(s, "Password successfully cached");
            return;
        },
        Err(e) => {
            show_message(s, format!("Could not cache password: {}", e).as_str());
            return;
        }
    }
}

#[cfg(feature = "pwmanclient")]
pub fn uncache_password(s: &mut Cursive, state_for_write_cache: Arc<Mutex<AppState>>) {
    let file_name = match state_for_write_cache.lock().unwrap().persister.get_canonical_path() {
        Ok(s) => s,
        Err(_) => {
            show_message(s, "Unable to determine canonical storage identity");    
            return 
        }
    };
    let client: Box<dyn PWManClient>;

    let c = make_pwman_client(file_name);
    if let Ok(cl) = c {
        client = cl;
    } else {
        show_message(s, "Unable to construct PWMAN client");
        return;
    }

    match client.reset_password() {
        Ok(_) => {
            state_for_write_cache.lock().unwrap().pw_is_chached = false;
            show_message(s, "Cache cleared");
            return;
        },
        Err(e) => {
            show_message(s, format!("Could not clear cache: {}", e).as_str());
            return;
        }
    }
}

#[cfg(not(feature = "pwmanclient"))]
pub fn password(s: &mut Cursive, _state_for_write_cache: Arc<Mutex<AppState>>) {
    show_message(s, "Sorry this feature is not available in this build") 
}

#[cfg(not(feature = "pwmanclient"))]
pub fn uncache_password(s: &mut Cursive, _state_for_write_cache: Arc<Mutex<AppState>>) {
    show_message(s, "Sorry this feature is not available in this build") 
}

#[cfg(feature = "pwmanclient")]
pub fn confirmation_dialog(sndr: Arc<Sender<String>>, password: String, client: Box<dyn PWManClient + Send + Sync>, ok_cb_with_state: Box<dyn Fn(&mut Cursive, &String, bool) + Send + Sync>) -> Dialog {
    let sender = sndr.clone();
    let sender2 = sndr.clone();

    let ok_cb = move |s: &mut Cursive| {
        ok_cb_with_state(s, &password, true);
    };

    let res = Dialog::new()
        .title("Rustpwman confirm password")
        .padding_lrtb(2, 2, 1, 1)
        .content(
            LinearLayout::horizontal()
                .child(TextView::new("Password has been read from PWMAN.\n\n             Continue?\n"))                        
        )
        .button("OK", ok_cb)
        .button("Clear PW", move |s| {
            match client.reset_password() {
                Ok(_) => {
                    let sender3 = sender2.clone();
                    s.add_layer(
                        Dialog::text("Cached password has been cleared. Quitting now ...")
                            .title("Rustpwman")
                            .button("Ok", move |s| {
                                s.pop_layer();
                                pwman_quit(s, sender3.clone(), String::from(""))
                            }),
                    );                    
                },
                Err(e) => {
                    show_message(s, format!("{}", e).as_str());
                }
            }            
        })
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from("")));

    return res;
}