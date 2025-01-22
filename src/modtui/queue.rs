/* Copyright 2025 Martin Grap

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
use super::AppState;
use super::get_selected_entry_name;
use super::show_message;
use super::format_pw_entry;


pub fn add(s: &mut Cursive, state_for_q_add: Arc<Mutex<AppState>>) {
    let entry_to_add = match get_selected_entry_name(s) {
        Some(e) => e,
        None => {
            return
        }
    };

    state_for_q_add.lock().unwrap().entry_queue.push(entry_to_add);
}

pub fn show(s: &mut Cursive, state_for_q_show: Arc<Mutex<AppState>>) {
    let state = state_for_q_show.lock().unwrap();
    if state.entry_queue.len() != 0 {
        let mut res = String::from("The following entries have been queued:\n\n");

        for i in &state.entry_queue {
            res.push_str(format!("{}\n", i).as_str());
        }

        show_message(s, res.as_str());
    } else {
        show_message(s, "Queue is empty!");
    }
}

pub fn clear(_s: &mut Cursive, state_for_q_clear: Arc<Mutex<AppState>>) {
    state_for_q_clear.lock().unwrap().entry_queue.clear();
}

fn get_entries_int(state_for_q_clear: Arc<Mutex<AppState>>, clear: bool) -> String {
    let mut state = state_for_q_clear.lock().unwrap();
    let mut res = String::from("");

    for i in &state.entry_queue {
        let entry_data = match state.store.get(i) {
            Some(t) => t,
            None => {
                continue;
            }
        };

        res.push_str(format_pw_entry(i, &entry_data).as_str());
        res.push_str("\n");
    }

    if clear {
        state.entry_queue.clear();
    }

    return res;
}
pub fn get_entries(state_for_q_clear: Arc<Mutex<AppState>>) -> String {
    return get_entries_int(state_for_q_clear, true);
}