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


use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, Panel, OnEventView, SelectView};
use cursive::traits::*;
use cursive::event::Key;

use super::AppState;
use super::show_message;
use super::get_selected_entry_name;
use crate::clip::set_clipboard;
use super::copy_pw_entry_contents;

const SELECT_VIEW: &str = "templ_key_select";
const NUM_SCROLL_ELEMENTS: usize = 6;
const DLG_TEMPL: &str = "templ_dialog";


use super::TEMPLATE_SEP;

pub fn parse_entry(entry: &String, keys: &Vec<String>) -> (HashMap<String, String>, HashMap<String, usize>) {
    let mut values: HashMap<String, String> = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();

    for line in entry.lines() {
        let trimmed = line.trim();
        for key in keys {
            let prefix = format!("{}{}", key, TEMPLATE_SEP);
            if trimmed.starts_with(prefix.as_str()) {
                let value = trimmed[prefix.len()..].trim().to_string();
                *counts.entry(key.clone()).or_insert(0) += 1;
                values.insert(key.clone(), value);
            }
        }
    }

    return (values, counts);
}

pub fn to_clipboard(s: &mut Cursive, state_for_copy_entry: Arc<Mutex<AppState>>, template_key: &String, show_confirmation: bool) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry");
            return;
        }
    };

    let h: String;
    let known_keys: Vec<String>;
    let content: String;
    let copy_command: String;

    {
        let state =  state_for_copy_entry.lock().unwrap();
        h = match state.store.get(&entry_name) {
            Some(c) => c,
            None => { show_message(s, "Unable to read value of entry"); return }
        };

        content = String::from(copy_pw_entry_contents(&entry_name, &h).trim());
        known_keys = state.template_strings.clone();
        copy_command = state.copy_command.clone();
    }

    let (kv, kv_count) = parse_entry(&content, &known_keys);
    if kv_count.get(template_key).is_none() {
        show_message(s, "Template string not found");
        return;
    }

    if let Some(c) = kv_count.get(template_key) {
        if c >= &2 {
            show_message(s, "Template string is ambiguous");
            return;
        }
    }

    // If parse works correctly there is exactly one suitable value in the kv hashmap
    let templ_val = kv.get(template_key).unwrap().clone();

    match set_clipboard(copy_command, Box::new(templ_val)) {
        true => {
            show_message(s, "Unable to set clipboad");
            return
        },
        false => {
            s.pop_layer();
            if show_confirmation {                
                show_message(s, "Contents of the selected entry copied to clipboard");
            }
        }
    }
}

pub fn do_select(s: &mut Cursive, state_for_select: Arc<Mutex<AppState>>) {
    let id_opt = match s.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.selected_id() }) {
        Some(i) => i,
        None => {show_message(s, "No element selected"); return; }
    };

    if let Some(id) = id_opt {
        let help = s.call_on_name(SELECT_VIEW, |view: &mut SelectView| -> Option<String> {
            match view.get_item(id) {
                Some(t) => Some(String::from(t.0)),
                _ => None
            }
        });

        let entry_name = match help {
            Some(Some(egal)) => egal,
            _ => {show_message(s, "No element selected"); return; }
        };

        to_clipboard(s, state_for_select, &entry_name, true);
    } else {
        show_message(s, "No element selected");
    }    
}

pub fn retrieve(s: &mut Cursive, state_for_templ_get: Arc<Mutex<AppState>>) {
    let state_for_select = state_for_templ_get.clone();
    let state_for_enter_callback = state_for_templ_get.clone();

    let known_template_keys = state_for_templ_get.lock().unwrap().template_strings.clone();

    let mut select_view = SelectView::<String>::new();

    for i in known_template_keys {
        select_view.add_item(i.clone(), i.clone());
    }

    let named_select_view = select_view
    .autojump()
    .with_name(SELECT_VIEW);

    let mut event_wrapped_select_view = OnEventView::new(named_select_view);
    event_wrapped_select_view.set_on_event(Key::Enter, move |s| { do_select(s, state_for_enter_callback.clone()); });

    let scroll_view = event_wrapped_select_view
    .scrollable()
    .fixed_height(NUM_SCROLL_ELEMENTS);

    let res = Dialog::new()
    .title("Rustpwman get templated value")
    .padding_lrtb(1, 1, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(
            Panel::new(scroll_view)
            .title("Tempale strings available")
        )
    )
    .button("Select", move |s| { 
        do_select(s, state_for_select.clone()); 
    })
    .button("Cancel", move |s| { s.pop_layer(); })
    .with_name(DLG_TEMPL);

    s.add_layer(res);  
}