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
use cursive::Cursive;
use cursive::views::{Dialog, TextView};

use super::AppState;
use super::show_message;
use crate::{CfgSource, VERSION_STRING};
use crate::fcrypt::{self, KdfId};


pub fn show(s: &mut Cursive, state_for_info: Arc<Mutex<AppState>>) {
    let num_entries = state_for_info.lock().unwrap().store.len();
    let mut msg_str = String::from("");
    let info2: String;
    let algo_name: &str;
    let config_file_name: String;
    let config_type: CfgSource;
    let password_chached: bool;
    let kdf_id: KdfId;
    
    info2 = match state_for_info.lock().unwrap().persister.get_canonical_path() {
        Ok(m) => m,
        Err(_) => String::from("Unknown")
    };

    {
        let s = state_for_info.lock().unwrap();
        let (deriver, id) = fcrypt::KdfId::Argon2.to_named_func();
        algo_name = (s.store.cr_gen)(deriver, id).algo_name();
        password_chached = s.pw_is_chached;
        config_file_name = s.cfg_name.clone();
        config_type = s.cfg_type;
        kdf_id = s.kdf_id;
    }

    msg_str.push_str(format!("Entry count  : {}\n", num_entries).as_str());
    msg_str.push_str(format!("Location     : {}\n", info2).as_str());
    msg_str.push_str(format!("Access method: {}\n", state_for_info.lock().unwrap().persister.get_type()).as_str());
    msg_str.push_str(format!("Cipher       : {}\n", algo_name).as_str());
    msg_str.push_str(format!("KDF          : {}\n", kdf_id.to_string()).as_str());
    msg_str.push_str(format!("PW chached   : {}\n", password_chached).as_str());
    msg_str.push_str(format!("Config file  : {}\n", config_file_name).as_str());
    msg_str.push_str(format!("Config ref by: {}\n", config_type).as_str());

    let res = Dialog::new()
    .title("Rustpwman info")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        TextView::new(msg_str))
    .button("OK", move |s| {
        s.pop_layer();
    });

    s.add_layer(res);
}

fn make_feature_string() -> String {
    let mut msg_str = String::from("");

    #[cfg(feature = "pwmanclient")]
    msg_str.push_str("- pwmanclient\n");

    #[cfg(feature = "pwmanclientux")]
    msg_str.push_str("- pwmanclientux\n");

    #[cfg(feature = "pwmanclientwin")]
    msg_str.push_str("- pwmanclientwin\n");

    #[cfg(feature = "webdav")]
    msg_str.push_str("- webdav\n");

    #[cfg(feature = "chacha20")]
    msg_str.push_str("- ChaCha20Poly1305\n");

    #[cfg(feature = "writebackup")]
    msg_str.push_str("- writebackup\n");

    #[cfg(feature = "qrcode")]
    msg_str.push_str("- qrcode\n");


    if msg_str == "" {
        msg_str.push_str("-- None --");
    }

    let mut user_msg = String::from("Active features:\n\n");
    user_msg.push_str(&msg_str);

    return user_msg;
}

pub fn about(s: &mut Cursive) {    
    let msg_str = format!("A simple password manager\n\nWritten by Martin Grap in 2021-2025\n\nVersion {}\n\nhttps://github.com/rmsk2/rustpwman\n\n", VERSION_STRING);

    let res = Dialog::new()
    .title("Rustpwman")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        TextView::new(msg_str)
        .center())
    .button("OK", move |s| {
        s.pop_layer();
    })
    .button("Features ...", |s| {
        show_message(s, &make_feature_string().as_str());
    });

    s.add_layer(res);
}