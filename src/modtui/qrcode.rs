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

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, EditView};
use cursive::traits::*;
use std::sync::{Arc, Mutex};
use super::AppState;
use super::show_message;
use super::get_selected_entry_name;
use qrcode::QrCode;
use image::Luma;

const QR_CODE_FILE_NAME: &str = "qrfile";

pub fn create(s: &mut Cursive, state_for_copy_entry: Arc<Mutex<AppState>>) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    };

    let h = match state_for_copy_entry.lock().unwrap().store.get(&entry_name) {
        Some(c) => c,
        None => { show_message(s, "Unable to read value of entry"); return }
    };

    let trimmed = h.trim();
    
    let code = match QrCode::new(trimmed) {
        Ok(c) => c,
        Err(_) => {
            show_message(s, "Unable to encode data as QR code"); 
            return
        }
    };

    let image = code.render::<Luma<u8>>().min_dimensions(200, 200).build();
    
    let res = Dialog::new()
    .title("Rustpwman save QR code")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please enter the name of a file to save QR code.\n\n"))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("Filename: "))
                .child(EditView::new()
                    .with_name(QR_CODE_FILE_NAME)
                    .fixed_width(60))        
        )
    )
    .button("Cancel", |s| { s.pop_layer(); })
    .button("OK", move |s| {
        let file_name = match s.call_on_name(QR_CODE_FILE_NAME, |view: &mut EditView| { view.get_content() }) {
            Some(name) => {
                name.clone()
            },
            None => { show_message(s, "Unable to read file name"); return }
        }; 

        if file_name.len() == 0 {
            show_message(s, "File name must not be empty"); 
            return
        }

        let result = image.save(file_name.as_str());

        match result {
            Ok(_) => {
                s.pop_layer();
                show_message(s, "Done"); 
            },
            Err(e) => {
                show_message(s, &format!("Unable to save QR code: {:?}", e));
            }
        };
    });

    s.add_layer(res);
}