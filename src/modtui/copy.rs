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


use std::rc::Rc;
use std::cell::RefCell;
use super::AppState;
use cursive::Cursive;
use super::show_message;
use super::get_selected_entry_name;
use crate::clip::set_clipboard;

pub fn entry(s: &mut Cursive, state_for_copy_entry: Rc<RefCell<AppState>>) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    };

    let mut content = match state_for_copy_entry.borrow().store.get(&entry_name) {
        Some(c) => c,
        None => { show_message(s, "Unable to read value of entry"); return }
    };

    content = format!("-------- {} --------\n{}", entry_name, content);

    match set_clipboard(String::from(state_for_copy_entry.borrow().copy_command.clone()), Box::new(content)) {
        true => {
            show_message(s, "Unable to set clipboad");
        },
        false => {
            show_message(s, "Contents of entry copied to clipboard");
        }
    }
}