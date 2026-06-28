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
use crate::clip::execute_viewer;

const SELECT_VIEW: &str = "templ_key_select";
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

                if value.len() > 0 {
                    *counts.entry(key.clone()).or_insert(0) += 1;
                    values.insert(key.clone(), value);
                }
            }
        }
    }

    return (values, counts);
}

fn retrieve_template_value(state_for_copy_entry: Arc<Mutex<AppState>>, template_key: &String, content: &String) -> Result<String, String> {
    let known_keys: Vec<String>;

    {
        let state = state_for_copy_entry.lock().unwrap();
        known_keys = state.template_strings.clone();
    }

    let (kv, kv_count) = parse_entry(content, &known_keys);
    match kv_count.get(template_key) {
        None => { return Err(String::from("Template string not found")); }
        Some(c) => {
            if *c >= 2 {
                return Err(String::from(format!("Template string is ambiguous. It appears {} times", c)));
            }
        }
    }

    // If parse works correctly there is exactly one suitable value in the kv hashmap
    let templ_val = kv.get(template_key).unwrap().clone();

    return Ok(templ_val);
}

fn get_selected_content(s: &mut Cursive, state_for_copy_entry: Arc<Mutex<AppState>>) -> Result<String, String> {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            return Err(String::from("Unable to determine selected entry"));
        }
    };

    let content: String;

    {
        let state =  state_for_copy_entry.lock().unwrap();
        let h = match state.store.get(&entry_name) {
            Some(c) => c,
            None => { return Err(String::from("Unable to read value of entry")); }
        };

        content = String::from(h.trim());
    }

    return Ok(content);
}

pub fn to_clipboard(s: &mut Cursive, state_for_copy_entry: Arc<Mutex<AppState>>, template_key: &String, close_parent: bool) {
    let content = match get_selected_content(s, state_for_copy_entry.clone()) {
        Ok(c) => c,
        Err(m) => { show_message(s, &m); return; }
    };

    let copy_command: String;

    {
        let state =  state_for_copy_entry.lock().unwrap();
        copy_command = state.copy_command.clone();
    }

    let templ_val = match retrieve_template_value(state_for_copy_entry.clone(), template_key, &content) {
        Err(m) => { show_message(s, &m); return; }
        Ok(v) => v
    };

    match set_clipboard(copy_command, Box::new(templ_val)) {
        true => { show_message(s, "Unable to set clipboad"); return },
        false => {
            if close_parent {
                s.pop_layer();
            } else {
                show_message(s, "Contents of the selected entry copied to clipboard");
            }
        }
    }
}

pub fn to_clip_close_parent(s: &mut Cursive, state_for_copy_entry: Arc<Mutex<AppState>>, template_key: &String) {
    to_clipboard(s, state_for_copy_entry, template_key, true);
}

pub fn to_clip_keep_parent(s: &mut Cursive, state_for_copy_entry: Arc<Mutex<AppState>>, template_key: &String) {
    to_clipboard(s, state_for_copy_entry, template_key, false);
}


pub fn open_as_url(s: &mut Cursive, state_for_copy_entry: Arc<Mutex<AppState>>, template_key: &String) {
    let content = match get_selected_content(s, state_for_copy_entry.clone()) {
        Ok(c) => c,
        Err(m) => { show_message(s, &m); return; }
    };

    let h: Option<String>;

    {
        let state =  state_for_copy_entry.lock().unwrap();
        h = state.viewer_prefix.clone();
    }

    let viewer_command = match h {
        None => { show_message(s, "No viewer defined"); return; },
        Some(val) => val
    };


    let templ_val = match retrieve_template_value(state_for_copy_entry.clone(), template_key, &content) {
        Err(m) => { show_message(s, &m); return; }
        Ok(v) => v
    };

    if !((templ_val.starts_with("https://")) || (templ_val.starts_with("http://"))) {
        show_message(s, "Value does not appear to be a URL");
        return;
    }

    match execute_viewer(&templ_val, Some(viewer_command.as_str())) {
        None => { return; },
        Some(msg) => {
            show_message(s, &msg);
            return;
        }
    }

}

pub fn do_select(s: &mut Cursive, state_for_select: Arc<Mutex<AppState>>, processor: fn(&mut Cursive, Arc<Mutex<AppState>>, &String)) {
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

        processor(s, state_for_select, &entry_name);
    } else {
        show_message(s, "No element selected");
    }    
}

pub fn retrieve(s: &mut Cursive, state_for_templ_get: Arc<Mutex<AppState>>) {
    let state_for_select = state_for_templ_get.clone();
    let state_for_open = state_for_templ_get.clone();
    let state_for_enter_callback = state_for_templ_get.clone();
    let state_for_f8_callback = state_for_templ_get.clone();
    let state_for_f9_callback = state_for_templ_get.clone();
    let state_for_retr_only = state_for_templ_get.clone();

    let known_template_keys = state_for_templ_get.lock().unwrap().template_strings.clone();
    let num_templ_strings = known_template_keys.len();

    let mut select_view = SelectView::<String>::new();

    for i in known_template_keys {
        select_view.add_item(i.clone(), i.clone());
    }

    let named_select_view = select_view
    .autojump()
    .with_name(SELECT_VIEW);

    let mut event_wrapped_select_view = OnEventView::new(named_select_view);
    event_wrapped_select_view.set_on_event(Key::Enter, move |s| { do_select(s, state_for_enter_callback.clone(), to_clip_close_parent); });
    event_wrapped_select_view.set_on_event(Key::F8, move |s| { do_select(s, state_for_f8_callback.clone(), to_clip_keep_parent); });
    event_wrapped_select_view.set_on_event(Key::F9, move |s| { do_select(s, state_for_f9_callback.clone(), open_as_url); });

    let scroll_view = event_wrapped_select_view
    .scrollable()
    .fixed_height(num_templ_strings.min(10));

    let res = Dialog::new()
    .title("Rustpwman templated values")
    .padding_lrtb(1, 1, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(
            Panel::new(scroll_view)
            .title("Template strings")
        )
    )
    .button("Retrieve and close", move |s| {
        do_select(s, state_for_select.clone(), to_clip_close_parent);
    })
    .button("Retrieve only", move |s| {
        do_select(s, state_for_retr_only.clone(), to_clip_keep_parent);
    })
    .button("Open as URL", move |s| {
        do_select(s, state_for_open.clone(), open_as_url);
    })
    .button("Cancel", move |s| { s.pop_layer(); })
    .with_name(DLG_TEMPL);

    s.add_layer(res);  
}