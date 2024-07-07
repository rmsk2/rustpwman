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
use cursive::views::{Dialog, LinearLayout, TextView, EditView};
use cursive::traits::*;

use super::AppState;
use super::show_message;
use super::get_selected_entry_name;
use super::display_entry;
use super::redraw_tui;
use super::visualize_if_modified;

const RENAME_EDIT_NAME: &str = "renamedit";

pub fn entry(s: &mut Cursive, state_for_rename_entry: Arc<Mutex<AppState>>) {
    let old_entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    };

    let res = Dialog::new()
    .title("Rustpwman rename entry")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new(format!("Please enter new name for '{}'.\n\n", old_entry_name)))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("New name: "))
                .child(EditView::new()
                    .content(old_entry_name.clone())
                    .with_name(RENAME_EDIT_NAME)
                    .fixed_width(40))
        )
    )
    .button("OK", move |s| {
        let new_entry_name = match s.call_on_name(RENAME_EDIT_NAME, |view: &mut EditView| {view.get_content()}) {
            Some(entry) => {
                if entry.len() == 0 {
                    show_message(s, "New entry name is empty"); 
                    return;
                }
                entry.clone()
            },
            None => { show_message(s, "Unable to read new entry name"); return }
        }; 


        if !state_for_rename_entry.lock().unwrap().store.entry_exists(&old_entry_name) {
            show_message(s, "Old entry does not exist"); 
            return;
        }

        if state_for_rename_entry.lock().unwrap().store.entry_exists(&new_entry_name) {
            show_message(s, "An entry with the new name already exists"); 
            return;
        }

        if !state_for_rename_entry.lock().unwrap().store.rename(&old_entry_name, &new_entry_name) {
            show_message(s, "Renaming entry failed"); 
            return;            
        }

        visualize_if_modified(s, state_for_rename_entry.clone());
        redraw_tui(s, state_for_rename_entry.clone());
        s.pop_layer();
        display_entry(s, state_for_rename_entry.clone(), &new_entry_name, true);
        show_message(s, "Entry renamed successfully. The renamed entry has been selected\n but you may need to scroll to it manually.");
    })
    .button("Cancel", |s| { s.pop_layer(); });                
    
    s.add_layer(res);


}
