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
use super::AppState;
use cursive::Cursive;
use super::show_message;
use super::get_selected_entry_name;
use crate::clip::set_clipboard;
use super::queue;
use super::format_pw_entry;

pub fn entry(s: &mut Cursive, state_for_copy_entry: Arc<Mutex<AppState>>, show_confirmation: bool) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    };

    let mut h = match state_for_copy_entry.lock().unwrap().store.get(&entry_name) {
        Some(c) => c,
        None => { show_message(s, "Unable to read value of entry"); return }
    };

    h = format_pw_entry(&entry_name, &h);
    let mut content = queue::get_entries(state_for_copy_entry.clone());
    content.push_str(h.as_str());

    match set_clipboard(String::from(state_for_copy_entry.lock().unwrap().copy_command.clone()), Box::new(content)) {
        true => {
            show_message(s, "Unable to set clipboad");
        },
        false => {
            if show_confirmation {
                show_message(s, "Contents of queue and selected entry copied to clipboard");
            }            
        }
    }
}