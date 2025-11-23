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
use std::process::Command;
use qrcode::QrCode;
use image::Luma;
use std::fs;

const QR_CODE_FILE_NAME: &str = "qrfile";


fn ask_for_deletion(s: &mut Cursive, file_name: String) {
    let dlg = Dialog::new()
    .title("Rustpwman delete QR code file")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("The following file was created:"))
        .child(TextView::new("\n"))
        .child(TextView::new(file_name.clone()))
        .child(TextView::new("\n"))
        .child(TextView::new("In order to not let a secret presist on disk it is advisable to delete"))
        .child(TextView::new("this file as soon as possible."))
        .child(TextView::new("\n"))
        .child(TextView::new("So scan the QR code and after that select 'Delete Now' to delete it."))
        .child(TextView::new("If you want to remove the file by hand later select 'Cancel'"))
    )
    .button("Cancel", |s| { s.pop_layer(); })            
    .button("Delete Now", move |s| {
        s.pop_layer();
        if let Err(e) = fs::remove_file(file_name.as_str()) {
            show_message(s, &format!("Unable to delete QR code file: {:?}", e)); 
        }
    });
    
    s.add_layer(dlg);
}

fn run_command(cmd: &str) -> Option<std::io::Error> {
    if cmd.len() == 0 {
        return Some(std::io::Error::new(std::io::ErrorKind::Other, "Command string not valid"));
    }

    let cmd_args = cmd.split_ascii_whitespace();
    let collection: Vec<&str> = cmd_args.collect(); 

    if collection.len() < 1 {
        return Some(std::io::Error::new(std::io::ErrorKind::Other, "Command string not valid"));
    }   

    match Command::new(collection[0]).args(collection[1..].into_iter()).spawn() {
        Ok(_) =>  {
            return None
        },
        Err(e) => {
            return Some(e)
        }
    };
}

fn execute_viewer(file_name: &String, cmd_prefix: Option<&str>) -> Option<String> {
    let res: Option<String>;
    let mut h: String;

    match cmd_prefix {
        None => {
            return None;
        },
        Some(prefix) => {
            h = String::from(prefix)
        }        
    };
    
    h.push_str(" ");
    h.push_str(file_name);
    
    res = match run_command(h.as_str()) {
        None => {
            None
        },
        Some(e) => {
            Some(format!("Unable to start QR code viewer: {:?}", e))
        }
    };
    
    return res;
}

pub fn create(s: &mut Cursive, state_for_create_qr_entry: Arc<Mutex<AppState>>) {
    let state_for_open_viewer = state_for_create_qr_entry.clone();

    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    };

    let h = match state_for_create_qr_entry.lock().unwrap().store.get(&entry_name) {
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
        .child(TextView::new("Please enter the name of the file in which to save the QR code.\n\n"))
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

        let mut f_name = String::from(file_name.as_str());

        if !f_name.ends_with(".png") {
            f_name.push_str(".png");
        }

        let result = image.save(f_name.as_str());

        let viewer_help = state_for_open_viewer.lock().unwrap().viewer_prefix.clone();

        let v_help: String;
        let mut viewer: Option<&str> = None;
        if let Some(v) = viewer_help {
            v_help = v.clone();
            viewer = Some(v_help.as_str());
        }

        match result {
            Ok(_) => {
                s.pop_layer();
                let msg = execute_viewer(&f_name, viewer);
                if let Some(error_message) = msg {
                    show_message(s, &error_message);
                    return
                } else {
                    ask_for_deletion(s, f_name);
                    return;
                }
            },
            Err(e) => {
                show_message(s, &format!("Unable to save QR code: {:?}", e));
                return
            }
        };
    });

    s.add_layer(res);
}