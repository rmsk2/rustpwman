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
use cursive::views::{Checkbox, Dialog, LinearLayout, NamedView, OnEventView, Panel, TextArea, TextView};
use cursive::event::{Event, EventResult, EventTrigger, Key};
use cursive::traits::*;
use cursive::theme::{self, Effects};
use cursive::theme::{Effect, PaletteColor};
use cursive::theme::ColorStyle;


use super::AppState;
use super::show_message;
use super::get_selected_entry_name;
use super::display_entry;
use super::visualize_if_modified;
use super::refocus_dlg_element;
use super::pwgenerate;
use crate::clip;

const TEXT_AREA_NAME: &str = "textareaedit";
const DLG_EDIT: &str = "edit_dialog";
const MARK_INDICATOR: &str = "mark_indicator";

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
    s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { view.set_cursor(cursor_pos) });
}


fn event_listener(view: &mut TextArea, event: &Event, mark: Arc<Mutex<Option<usize>>>) -> Option<EventResult> {
    let current_mark_set = !mark.lock().unwrap().is_none();
    let mut new_mark_set = current_mark_set;
    let result: EventResult;
    
    match event {
        Event::Key(Key::F8) => {
            let cursor_pos = view.cursor();
            *mark.lock().unwrap() = Some(cursor_pos);
            // Do not forward event to TextArea
            result = EventResult::Consumed(None);
            new_mark_set = true;
        },
        Event::Key(Key::F9) => {
            *mark.lock().unwrap() = None;
            // Do not forward event to TextArea
            result = EventResult::Consumed(None);
            new_mark_set = false;
        },
        _ => {
            let content_before = String::from(view.get_content());
            // let TextArea process the event
            result = view.on_event(event.clone());

            if view.get_content() != content_before {
                *mark.lock().unwrap() = None;
                new_mark_set = false;
            }
        }
    }

    if new_mark_set != current_mark_set {
        let cb_change_indicator = move |s: &mut Cursive| {
            s.call_on_name(MARK_INDICATOR, |view: &mut Checkbox| { view.set_checked(new_mark_set); });            
        };

        // Make Cursive execute the callback when returning from this call
        return Some(result.and(EventResult::with_cb(cb_change_indicator)))
    }

    return Some(result);
}

fn reset_and_visualize_mark(s: &mut Cursive, mark: Arc<Mutex<Option<usize>>>) {
    *mark.lock().unwrap() = None;
    s.call_on_name(MARK_INDICATOR, |view: &mut Checkbox| { view.set_checked(false) });
}

fn handle_copy_cut(s: &mut Cursive, state_for_copy:  Arc<Mutex<AppState>>, marked_position_for_copy: Arc<Mutex<Option<usize>>>, do_cut: bool) {
    let mark = marked_position_for_copy.clone();
    let val: Option<usize>;

    {
        let h = mark.lock().unwrap();
        val = *h;
    }

    if val.is_none() {
        show_message(s, "No mark set");
        refocus_dlg_element(s, DLG_EDIT, TEXT_AREA_NAME);
        return
    }

    let mark_pos = val.unwrap();

    let mut entry_text = match s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { String::from(view.get_content()) }) {
        Some(text_val) => {
            text_val
        },
        None => { show_message(s, "Unable to read entry text"); return }
    };

    let cursor_pos_opt = s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { view.cursor() });
    if cursor_pos_opt.is_none() {
        show_message(s, "Unable to read cursor position"); return
    }

    let cursor_pos = cursor_pos_opt.unwrap();
    let start_pos = mark_pos.min(cursor_pos);
    let end_pos = mark_pos.max(cursor_pos);

    if start_pos == end_pos {
        show_message(s, "Selection is empty");
        refocus_dlg_element(s, DLG_EDIT, TEXT_AREA_NAME);
        return;
    }

    if let Some(selected) = entry_text.get(start_pos..end_pos) {
        if clip::set_clipboard(String::from(state_for_copy.lock().unwrap().copy_command.clone()), Box::new(String::from(selected))) {
            show_message(s, "Unable to set clipboad");
            return;
        } else {
            reset_and_visualize_mark(s, mark);

            if !do_cut {
                show_message(s, "Marked contents copied to clipboard");
            } else {
                let _ = entry_text.drain(start_pos..end_pos).collect::<String>();
                s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { view.set_content(entry_text) });
                s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { view.set_cursor(start_pos) });
            }

            refocus_dlg_element(s, DLG_EDIT, TEXT_AREA_NAME);
        }
    }
}

pub fn entry(s: &mut Cursive, state_for_edit_entry: Arc<Mutex<AppState>>, entry_name_external: Option<Arc<String>>) {
    let entry_to_edit: String;
    
    match entry_name_external {
        Some(e) => {entry_to_edit = String::from(e.as_str()); },
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
    let state_for_copy = state_for_edit_entry.clone();
    let state_for_cut = state_for_edit_entry.clone();

    let mut eff = Effects::empty();
    eff.insert(Effect::Simple);

    let name_style = theme::Style {
        effects: eff,
        color: ColorStyle::new(PaletteColor::View, PaletteColor::TitleSecondary),
    };

    let mp: Option<usize> = None;
    let marked_position = Arc::new(Mutex::new(mp));
    let marked_position_for_cb = marked_position.clone();
    let marked_position_for_copy = marked_position.clone();
    let marked_position_for_cut = marked_position.clone();

    let text_area = TextArea::new()
                    .content(content)
                    .with_name(TEXT_AREA_NAME);

    let mut event_wrapped_text_area = OnEventView::new(text_area);
    event_wrapped_text_area.set_on_pre_event_inner(EventTrigger::any(), move |view: &mut NamedView<TextArea>, event: &Event| -> Option<EventResult> {
        let mut inner = view.get_mut();
        return event_listener(&mut inner, event, marked_position_for_cb.clone());
    });

    let event_wrapped_text_area = event_wrapped_text_area
        .fixed_width(80)
        .min_height(25);

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
                Panel::new(event_wrapped_text_area)
                .title("Text of entry"))
        )
        .child(
            LinearLayout::horizontal()
            .child(TextView::new("Mark set "))
            .child(
                Checkbox::new()
                    .disabled()
                    .with_name(MARK_INDICATOR)
            )            
        )
    )
    .button("OK", move |s| {
        let entry_text = match s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { String::from(view.get_content()) }) {
            Some(text_val) => {
                if text_val.len() == 0 {
                    show_message(s, "Entry text is empty");
                    refocus_dlg_element(s, DLG_EDIT, TEXT_AREA_NAME);
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
    })
    .button("Copy ...", move |s: &mut Cursive| {
        handle_copy_cut(s, state_for_copy.clone(), marked_position_for_copy.clone(), false);
    })
    .button("Cut", move |s: &mut Cursive| {
        handle_copy_cut(s, state_for_cut.clone(), marked_position_for_cut.clone(), true);
    })        
    .button("Paste", move |s: &mut Cursive| {
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
        refocus_dlg_element(s, DLG_EDIT, TEXT_AREA_NAME);
    })
    .button("Insert Password ...", move |s: &mut Cursive| {
        pwgenerate::generate_password(s, state_for_gen_pw.clone());
        refocus_dlg_element(s, DLG_EDIT, TEXT_AREA_NAME);
    })    
    .button("Clear", move |s| {
        s.call_on_name(TEXT_AREA_NAME, |view: &mut TextArea| { view.set_content(String::from("")) });
        refocus_dlg_element(s, DLG_EDIT, TEXT_AREA_NAME);
    })
    .button("Help ...", move |s| { 
        show_message(s, "Use F8 to set a mark at the current cursor position.\n\nThen use <Copy ...> or <Cut> to cut or copy all text\nbetween the mark and the current cursor position.\n\nThe character at the start position is part of the selection.\nThe character at the end position is not.\n\nPress F9 to reset the mark.");
        refocus_dlg_element(s, DLG_EDIT, TEXT_AREA_NAME);
    })    
    .button("Cancel", move |s| { 
        s.pop_layer();
    })
    .with_name(DLG_EDIT);
    
    s.add_layer(res);
}
