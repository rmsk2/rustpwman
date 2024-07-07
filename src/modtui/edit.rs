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
use cursive::views::{Dialog, LinearLayout, TextView, TextArea, Panel};
use cursive::traits::*;
use cursive::theme::{self, Effects};
use cursive::theme::{Effect, PaletteColor};
use cursive::theme::ColorStyle;

use super::AppState;
use super::show_message;
use super::get_selected_entry_name;
use super::display_entry;
use super::visualize_if_modified;
use super::pwgenerate;
use crate::clip;

const TEXT_AREA_NAME: &str = "textareaedit";

pub fn insert_into_entry(s: &mut Cursive, new_pw: String) {
    let mut entry_text = match s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { String::from(view.get_content()) }) {
        Some(text_val) => {
            text_val
        },
        None => { show_message(s, "Unable to read entry text"); return }
    };

    let cursor_pos = match s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { view.cursor() }) {
        Some(p) => {
            p
        },
        None => { show_message(s, "Unable to read cursor position"); return }
    };

    entry_text.insert_str(cursor_pos, new_pw.as_str());

    s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { view.set_content(entry_text) });

    match s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { view.set_cursor(cursor_pos) }) {
        Some(_) => {
            
        },
        None => { show_message(s, "Unable to set cursor position"); return }
    };        

}

pub fn entry(s: &mut Cursive, state_for_edit_entry: Arc<Mutex<AppState>>, entry_name_external: Option<Arc<String>>) {
    let entry_to_edit: String;
    let mut show_scroll_message = false;
    
    match entry_name_external {
        Some(e) => {entry_to_edit = String::from(e.as_str()); show_scroll_message = true;},
        None => {
            match get_selected_entry_name(s) {
                Some(name) => {entry_to_edit = name},
                None => {
                    show_message(s, "Unable to determine selected entry"); 
                    return; 
                }
            };
        }
    }

    let content = match state_for_edit_entry.lock().unwrap().store.get(&entry_to_edit) {
        Some(c) => c,
        None => { show_message(s, "Unable to read value of entry"); return }
    };

    let state_for_gen_pw = state_for_edit_entry.clone();
    let state_for_paste = state_for_edit_entry.clone();

    let mut eff = Effects::empty();
    eff.insert(Effect::Simple);

    let name_style = theme::Style {
        //effects: enumset::enum_set!(Effect::Simple),
        effects: eff,
        color: ColorStyle::new(PaletteColor::View, PaletteColor::TitleSecondary),
    };

    let res = Dialog::new()
    .title("Rustpwman enter new text")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(
            LinearLayout::horizontal()
            .child(TextView::new("Please enter new text for entry "))
            .child(TextView::new(entry_to_edit.as_str())
                .style(name_style))
        )
        .child(TextView::new("\n"))
        .child(
            LinearLayout::horizontal()
                .child(
                Panel::new(
                    TextArea::new()
                    .content(content)
                    .with_name(TEXT_AREA_NAME)
                    .fixed_width(80)
                    .min_height(25))
                .title("Text of entry"))
        )
    )
    .button("OK", move |s| {
        let entry_text = match s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { String::from(view.get_content()) }) {
            Some(text_val) => {
                if text_val.len() == 0 {
                    show_message(s, "Entry text is empty"); 
                    return;
                }
                text_val
            },
            None => { show_message(s, "Unable to read entry text"); return }
        }; 

        state_for_edit_entry.lock().unwrap().store.modify(&entry_to_edit, &entry_text);
        visualize_if_modified(s, state_for_edit_entry.clone());
        display_entry(s, state_for_edit_entry.clone(), &entry_to_edit, true);

        s.pop_layer();

        if show_scroll_message {
            show_message(s, "Entry created successfully. It has been selected\n but you may need to scroll to it manually.");            
        }
    })
    .button("Insert Password ...", move |s: &mut Cursive| {
        pwgenerate::generate_password(s, state_for_gen_pw.clone());
    })
    .button("Paste clipboard", move |s: &mut Cursive| {
        let pasted_txt: String;
        let paste_cmd: &String;

        {
            let app_state = &state_for_paste.lock().unwrap();
            paste_cmd = &app_state.paste_command;

            pasted_txt = match clip::get_clipboard(&paste_cmd.as_str()) {
                Some(t) => t,
                None => {
                    show_message(s, "Unable to get clipboard contents");
                    return;                
                }
            };
        }

        insert_into_entry(s, pasted_txt);
    })    
    .button("Cancel", move |s| { 
        s.pop_layer(); 
        if show_scroll_message {
            show_message(s, "Entry created successfully. It has been selected\n but you may need to scroll to it manually.");            
        }  
    });                
    
    s.add_layer(res);
}
