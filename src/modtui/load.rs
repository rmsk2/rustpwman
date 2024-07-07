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



use std::fs;

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, EditView};
use cursive::traits::*;
use std::sync::{Arc, Mutex};

use super::AppState;
use super::show_message;
use super::get_selected_entry_name;
use super::display_entry;
use super::get_special_styles;
use super::visualize_if_modified;

const EDIT_FILE_NAME: &str = "editfile";

pub fn entry(s: &mut Cursive, state_for_add_entry: Arc<Mutex<AppState>>) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    }; 

    let (danger_style, reverse_style) = get_special_styles();    

    let res = Dialog::new()
    .title("Rustpwman load entry from file")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please enter the name of a file to load.\n\n"))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("Filename: "))
                .child(EditView::new()
                    .with_name(EDIT_FILE_NAME)
                    .fixed_width(60))        
        )
        .child(TextView::new("\n"))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("Entry "))
                .child(TextView::new(entry_name.as_str())
                    .style(reverse_style))
                .child(TextView::new(" will be "))
                .child(TextView::new("OVERWRITTEN")
                    .style(danger_style))
                .child(TextView::new(". Do you want to proceed?"))
        )
    )
    .button("Cancel", |s| { s.pop_layer(); })                
    .button("OK", move |s| {
        let file_name = match s.call_on_name(EDIT_FILE_NAME, |view: &mut EditView| { view.get_content() }) {
            Some(name) => {
                name.clone()
            },
            None => { show_message(s, "Unable to read file name"); return }
        }; 

        let value = match fs::read_to_string(&file_name[..]) {
            Ok(s) => s,
            Err(e) => {
                show_message(s, &format!("Unable to read file: {:?}", e)); 
                return;
            }
        };

        state_for_add_entry.lock().unwrap().store.modify(&entry_name, &value);
        s.pop_layer();
        visualize_if_modified(s, state_for_add_entry.clone());
        display_entry(s, state_for_add_entry.clone(), &entry_name, true);
    });
    
    s.add_layer(res);
}
