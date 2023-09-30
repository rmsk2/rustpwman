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

pub const PW_MAX_SEC_LEVEL: usize = 24;

const PW_WIDTH: usize = 35;
pub const PW_SEC_LEVEL: usize = 9;
const EDIT_NAME: &str = "nameedit";
const TEXT_AREA_MAIN: &str = "entrytext";
const TEXT_AREA_NAME: &str = "textareaedit";
const SCROLL_VIEW: &str = "scrollview";
const SELECT_VIEW: &str = "entrylist";
const PANEL_AREA_MAIN: &str = "entrytitle";
const TEXT_AREA_TITLE: &str = "texttitle";
const EDIT_FILE_NAME: &str = "editfile";
const RENAME_EDIT_NAME: &str = "renamedit";
const SLIDER_SEC_NAME: &str = "securityslider";
const BITS_SEC_VALUE: &str = "securitybits";

pub const DEFAULT_PASTE_CMD: &str = "xsel -ob";

use crate::VERSION_STRING;
use cursive::theme::ColorStyle;
use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, TextView, EditView, SelectView, TextArea, Panel, SliderView, RadioGroup, RadioButton, DialogFocus};
use cursive::Cursive;
use cursive::event::EventResult;
use cursive::menu::Tree;
use cursive::align::HAlign;
use cursive::event::Key;
use cursive::reexports::enumset;
use cursive::theme;
use cursive::theme::{ColorType, Effect, Color, PaletteColor};

use std::rc::Rc;
use std::cell::RefCell;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::fs;
use std::collections::HashMap;
use cursive::view::Selector::Name;

use crate::pwgen;
use crate::pwgen::GenerationStrategy;
use crate::pwgen::PasswordGenerator;
use crate::fcrypt::KeyDeriver;
use crate::fcrypt;
use crate::jots;
#[cfg(feature = "pwmanclient")]
use crate::pwman_client::PWManClient;
#[cfg(feature = "pwmanclientux")]
use crate::pwman_client_ux::UDSClient;
#[cfg(feature = "pwmanclientwin")]
use crate::pwman_client_win::UDSClientWin;

pub fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

#[cfg(feature = "pwmanclientux")]
fn make_pwman_client(file_name: String) -> std::io::Result<Box<dyn PWManClient>>{
    match UDSClient::new(file_name) {
        Ok(c) => return Ok(Box::new(c)),
        Err(e) => return Err(e)
    }
}

#[cfg(feature = "pwmanclientwin")]
fn make_pwman_client(file_name: String) -> std::io::Result<Box<dyn PWManClient>>{
    match UDSClientWin::new(file_name) {
        Ok(c) => return Ok(Box::new(c)),
        Err(e) => return Err(e)
    }
}

pub struct AppState {
    store: jots::Jots,
    password: Option<String>,
    file_name: String,
    dirty: bool,
    pw_gens: HashMap<GenerationStrategy, Box<dyn PasswordGenerator>>,
    default_security_level: usize,
    default_generator: GenerationStrategy,
    paste_command: String
}

impl AppState {
    pub fn new(s: jots::Jots, f_name: &String, generators: HashMap<GenerationStrategy, Box<dyn PasswordGenerator>>, default_sec: usize, default_gen: GenerationStrategy, paste_cmd: &String) -> Self {
        return AppState {
            store: s,
            password: None,
            file_name: f_name.clone(),
            dirty: false,
            pw_gens: generators,
            default_security_level: default_sec,
            default_generator: default_gen,
            paste_command: paste_cmd.clone()
        }
    }

    pub fn get_default_bits(&self) -> usize {
        return self.default_security_level;
    }   
}

pub fn main_gui(data_file_name: String, default_sec_bits: usize, derive_func: KeyDeriver, deriver_id: fcrypt::KdfId, default_pw_gen: GenerationStrategy, paste_cmd: String) {
    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    let capture_file_name = data_file_name.clone();
    let mut siv = cursive::default();
    let sender = Rc::new(tx);
    let sender_main = sender.clone();

    let pw_callback = Box::new(move |s: &mut Cursive, password: &String| {
        let jots_store = jots::Jots::new(derive_func, deriver_id);
        let f_name = capture_file_name.clone();
        let mut generators: HashMap<GenerationStrategy, Box<dyn PasswordGenerator>> = HashMap::new();

        for i in pwgen::GenerationStrategy::get_known_ids() {
            generators.insert(i, i.to_creator()());
        }

        let state = AppState::new(jots_store, &f_name, generators, default_sec_bits, default_pw_gen, &paste_cmd);

        if let Some(state_after_open) = open_file(s, password, state) {
            s.pop_layer(); // Close password, file init or confirmation dialog
            main_window(s, state_after_open, sender_main.clone());
        }
    });

    #[cfg(feature = "pwmanclient")]
    if path_exists(&data_file_name) {
        let file_name_for_uds_client = data_file_name.clone();

        match make_pwman_client(file_name_for_uds_client.clone()) {
            Ok(c) => {
                match c.get_password() {
                    Ok(password) => {
                        let d = password_read_from_pwman_dialog(sender.clone(), password.clone(), c, pw_callback);
                        siv.add_layer(d);
                    },
                    Err(_) => {                        
                        let d = password_entry_dialog(sender.clone(), pw_callback);
                        siv.add_layer(d);        
                    }
                }
            }
            Err(_) => {                
                let d = password_entry_dialog(sender.clone(), pw_callback);
                siv.add_layer(d);
            }
        };
    } else {
        let d = file_init_dialog(sender.clone(), pw_callback);
        siv.add_layer(d);
    }

    #[cfg(not(feature = "pwmanclient"))]
    if path_exists(&data_file_name) {
        let d = password_entry_dialog(sender.clone(), pw_callback);
        siv.add_layer(d);
    } else {
        let d = file_init_dialog(sender.clone(), pw_callback);
        siv.add_layer(d);
    }

    siv.run();

    let message = match rx.recv() {
        Ok(s) => s,
        Err(_) => String::from("Unable to receive message")
    };

    println!("{}", message);
}

fn do_quit(s: &mut Cursive, sender: Rc<Sender<String>>, message: String) {
    match sender.send(message) {
        Ok(_) => (),
        Err(_) => ()
    };
    
    s.quit();
}

fn pwman_quit(s: &mut Cursive, sender: Rc<Sender<String>>, message: String, dirty_bit: bool)
{
    let msg = message.clone();
    let sndr = sender.clone();

    if dirty_bit {
        s.add_layer(
            Dialog::text("There are unsaved changes. Continue anyway?")
                .title("Rustpwman")
                .button("Yes", move |s: &mut Cursive| {
                    s.pop_layer();
                    do_quit(s, sndr.clone(), msg.clone());
                })
                .button("No", |s| {
                    s.pop_layer();
                })           
        );
    } else {
        do_quit(s, sender, message);
    }
}

fn show_message(siv: &mut Cursive, msg: &str) {
    siv.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Ok", |s| {
                s.pop_layer();
            }),
    );
}

fn display_entry(siv: &mut Cursive, state: Rc<RefCell<AppState>>, entry_name: &String, do_select: bool) {
    if entry_name == "" {
        return;
    }

    let entry_text: String;
    let pos: usize;

    {
        let store = &state.borrow().store;

        let positions = 0..store.into_iter().count();
        let find_res = store.into_iter().zip(positions).find(|i| entry_name == (*i).0 );

        pos = find_res.unwrap().1;
        entry_text = store.get(entry_name).unwrap();
    }

    if do_select {
        match siv.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.set_selection(pos) }) {
            Some(cb) => cb(siv),
            None => {
                show_message(siv, "Unable to set selection"); 
                return;
            }
        }     
    } else {
        siv.call_on_name(TEXT_AREA_MAIN, |view: &mut TextArea| { view.set_content(entry_text.clone()); });
        siv.call_on_name(TEXT_AREA_TITLE, |view: &mut TextArea| { view.set_content(entry_name.clone()); });
    }
}

fn fill_tui(siv: &mut Cursive, state: Rc<RefCell<AppState>>) {
    let mut count = 0;
    let mut initial_entry = String::from("");

    siv.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.clear(); } );
    siv.call_on_name(TEXT_AREA_MAIN, |view: &mut TextArea| { view.set_content(""); });
    siv.call_on_name(TEXT_AREA_TITLE, |view: &mut TextArea| { view.set_content(""); });

    {
        let store = &state.borrow().store;

        for i in store {
            if count == 0 {
                 initial_entry = i.clone();
            }
    
            siv.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.add_item(i.clone(), i.clone()); } );
    
            count += 1;
        }    
    }
    
    display_entry(siv, state.clone(), &initial_entry, true);
}

fn get_selected_entry_name(s: &mut Cursive) -> Option<String> {
    let id_opt = match s.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.selected_id() }) {
        Some(i) => i,
        None => None
    };

    if let Some(id) = id_opt {
        let help = s.call_on_name(SELECT_VIEW, |view: &mut SelectView| -> Option<String> { 
            match view.get_item(id) {
                Some(t) => Some(String::from(t.0)),
                _ => None
            }
        });

        return match help {
            Some(Some(egal)) => Some(egal),
            _ => None
        }
    } else {
        return None;
    }
}

fn process_save_command(s: &mut Cursive, state_temp_save: Rc<RefCell<AppState>>) {
    let password = match state_temp_save.borrow().password.clone() {
        Some(p) => p,
        None => { show_message(s, "Unable to read password"); return; }
    };

    let mut mut_state = state_temp_save.borrow_mut();
    let file_name = mut_state.file_name.clone();

    match mut_state.store.to_enc_file(&file_name, &password) {
        Err(e) => { 
            show_message(s, &format!("Unable to save: {:?}", e)); 
            return; 
        }
        _ => {
            mut_state.dirty = false
        }
    };
}

fn delete_entry(s: &mut Cursive, state_temp_del: Rc<RefCell<AppState>>) { 
    let (danger_style, reverse_style) = get_special_styles();    

    match get_selected_entry_name(s) {
        Some(name) => {
            let res = Dialog::new()
            .title("Rustpwman delete entry")
            .padding_lrtb(2, 2, 1, 1)
            .content(
                LinearLayout::vertical()
                .child(
                    LinearLayout::horizontal()
                    .child(TextView::new("The Entry "))
                    .child(TextView::new(name.as_str())
                        .style(reverse_style))
                        .child(TextView::new(" will be "))
                        .child(TextView::new("DELETED")
                            .style(danger_style))    
                        .child(TextView::new(". Do you want to proceed?"))
                )
            )
            .button("Cancel", |s| { s.pop_layer(); })            
            .button("OK", move |s| {
                state_temp_del.borrow_mut().store.remove(&name);
                state_temp_del.borrow_mut().dirty = true;
                fill_tui(s, state_temp_del.clone());
                s.pop_layer();
                show_message(s, "Entry deleted successfully. The first remaning element has been selected\nYou may need to scroll to it manually."); 
            });
            
            s.add_layer(res); 
        },
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    } 
}

fn clear_entry(s: &mut Cursive, state_temp_clear: Rc<RefCell<AppState>>) { 
    let (danger_style, reverse_style) = get_special_styles(); 

    match get_selected_entry_name(s) {
        Some(name) => {
            let res = Dialog::new()
            .title("Rustpwman clear entry")
            .padding_lrtb(2, 2, 1, 1)
            .content(
                LinearLayout::vertical()
                .child(
                    LinearLayout::horizontal()
                    .child(TextView::new("The Entry "))
                    .child(TextView::new(name.as_str())
                        .style(reverse_style))
                        .child(TextView::new(" will be "))
                        .child(TextView::new("CLEARED")
                            .style(danger_style))    
                        .child(TextView::new(". Do you want to proceed?"))
                )
            )
            .button("Cancel", |s| { s.pop_layer(); })            
            .button("OK", move |s| {
                let empty = String::from("Empty entry\n");
                state_temp_clear.borrow_mut().store.insert(&name, &empty);
                state_temp_clear.borrow_mut().dirty = true;
                s.pop_layer();
                display_entry(s, state_temp_clear.clone(), &name, true);
            });
            
            s.add_layer(res); 
        },
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    } 
}

fn add_entry(s: &mut Cursive, state_for_add_entry: Rc<RefCell<AppState>>) {
    let res = Dialog::new()
    .title("Rustpwman enter new entry name")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please enter a new name for an entry.\n\n"))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("New name: "))
                .child(EditView::new()
                    .with_name(EDIT_NAME)
                    .fixed_width(40))
        )
    )
    .button("OK", move |s| {
        let entry_name = match s.call_on_name(EDIT_NAME, |view: &mut EditView| {view.get_content()}) {
            Some(entry) => {
                if entry.len() == 0 {
                    show_message(s, "Entry is empty"); 
                    return;
                }
                entry.clone()
            },
            None => { show_message(s, "Unable to read new entry"); return }
        }; 

        let old_entry: Option<String>;

        {
            old_entry = state_for_add_entry.borrow().store.get(&entry_name);
        }

        match old_entry {
            Some(_) => { show_message(s, "Entry already exists"); return },
            None => {
                let new_text = String::from("New entry\n");
                state_for_add_entry.borrow_mut().store.insert(&entry_name, &new_text);
                state_for_add_entry.borrow_mut().dirty = true;
                fill_tui(s, state_for_add_entry.clone());
                s.pop_layer();

                display_entry(s, state_for_add_entry.clone(), &String::from(entry_name.as_str()), true);
                edit_entry(s, state_for_add_entry.clone(), Some(entry_name));
            }
        }
    })
    .button("Cancel", |s| { s.pop_layer(); });                
    
    s.add_layer(res);
}

fn get_special_styles() -> (theme::Style, theme::Style) {
    let danger_style = theme::Style {
        effects: enumset::enum_set!(Effect::Reverse),
        color: ColorStyle::new(ColorType::Color(Color::Rgb(255,0,0)), ColorType::Color(Color::Rgb(255, 255, 255))),
    };

    let reverse_style = theme::Style {
        effects: enumset::enum_set!(Effect::Simple),
        color: ColorStyle::new(ColorType::Color(Color::Rgb(255, 255, 255)), PaletteColor::Background),
    };

    return (danger_style, reverse_style);    
}

fn load_entry(s: &mut Cursive, state_for_add_entry: Rc<RefCell<AppState>>) {
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

        state_for_add_entry.borrow_mut().store.insert(&entry_name, &value);
        state_for_add_entry.borrow_mut().dirty = true;
        s.pop_layer();
        display_entry(s, state_for_add_entry.clone(), &entry_name, true);
    });
    
    s.add_layer(res);
}

fn show_sec_bits(s: &mut Cursive, val: usize) {
    s.call_on_name(BITS_SEC_VALUE, |view: &mut TextArea| {
        let out = format!("{}", (val + 1) * 8);
        view.set_content(out.clone());
    });
}

fn select_default_pw_generator_type(s: &mut Cursive, selector: &mut HashMap<GenerationStrategy, &mut RadioButton<GenerationStrategy>>, def_generator: GenerationStrategy) -> bool {
    let event_result = match selector.get_mut(&def_generator) {
        Some(button) => button.select(),
        None => {
            show_message(s, "Default password generator not found"); 
            return false; 
        }
    };

    match event_result {
        EventResult::Ignored => {
            show_message(s, "Unable to select default password generator"); 
            return false; 
        },
        EventResult::Consumed(c) => {
            match c {
                Some(cb) => { cb(s); true },
                None => true
            }
        }
    }
}

fn generate_password(s: &mut Cursive, state_for_gen_pw: Rc<RefCell<AppState>>) {
    let sec_bits = state_for_gen_pw.borrow().get_default_bits();
    let default_strategy = state_for_gen_pw.borrow().default_generator;

    let mut strategy_group: RadioGroup<GenerationStrategy> = RadioGroup::new();
    let mut radio_buttons: Vec<(GenerationStrategy, RadioButton<GenerationStrategy>)> = Vec::new();

    {
        for i in &GenerationStrategy::get_known_ids() {
            let b = strategy_group.button(*i, i.to_str());
            radio_buttons.push((*i, b));
        }

        let mut selector: HashMap<GenerationStrategy, &mut RadioButton<GenerationStrategy>> = HashMap::new();

        for i in &mut radio_buttons {
            selector.insert(i.0, &mut i.1);
        }
    
        if !select_default_pw_generator_type(s, &mut selector, default_strategy) {
            return;
        }
    }

    let mut linear_layout = LinearLayout::horizontal()
        .child(TextView::new("Contained characters: "));

    for i in radio_buttons {
        linear_layout.add_child(i.1);
        linear_layout.add_child(TextView::new(" "));
    }

    let res = Dialog::new()
    .title("Rustpwman generate password")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please select parameters for password generation.\n\n"))
        .child(LinearLayout::horizontal()
            .child(TextView::new("Security level "))
            .child(TextArea::new()
                .content("")
                .disabled()
                .with_name(BITS_SEC_VALUE)
                .fixed_height(1)
                .fixed_width(4)
            )            
            .child(TextView::new("Bits: "))
            .child(SliderView::horizontal(PW_MAX_SEC_LEVEL)
                .value(sec_bits)
                .on_change(|s, slider_val| { show_sec_bits(s, slider_val) })
                .with_name(SLIDER_SEC_NAME))
        )
        .child(TextView::new("\n"))
        .child(linear_layout)
    )
    .button("OK", move |s| {
        let rand_bytes = match s.call_on_name(SLIDER_SEC_NAME, |view: &mut SliderView| { view.get_value() }) {
            Some(v) => v,
            None => { show_message(s, "Unable to determine security level"); return }
        };

        let new_pw: String;

        {
            let generator_map: &mut HashMap<GenerationStrategy, Box<dyn PasswordGenerator>> = &mut state_for_gen_pw.borrow_mut().pw_gens;
            
            let generator: &mut Box<dyn PasswordGenerator> = match generator_map.get_mut(&strategy_group.selection()) {
                None => { show_message(s, "Unable create generator"); return },
                Some(g) => g
            };
    
            new_pw = match generator.gen_password(rand_bytes + 1) {
                Some(pw) => pw,
                None => {
                    show_message(s, "Unable to generate password"); 
                    return;
                }
            };
        }

        insert_into_entry(s, new_pw);
        s.pop_layer();        
    })
    .button("Cancel", |s| { s.pop_layer(); });
    
    s.add_layer(res);
    show_sec_bits(s, sec_bits);
}

fn insert_into_entry(s: &mut Cursive, new_pw: String) {
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

fn edit_entry(s: &mut Cursive, state_for_edit_entry: Rc<RefCell<AppState>>, entry_name_external: Option<Rc<String>>) {
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

    let show_scroll_message_2 = show_scroll_message.clone();

    let content = match state_for_edit_entry.borrow().store.get(&entry_to_edit) {
        Some(c) => c,
        None => { show_message(s, "Unable to read value of entry"); return }
    };

    let state_for_gen_pw = state_for_edit_entry.clone();
    let state_for_paste = state_for_edit_entry.clone();

    let name_style = theme::Style {
        effects: enumset::enum_set!(Effect::Simple),
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

        state_for_edit_entry.borrow_mut().store.insert(&entry_to_edit, &entry_text);
        state_for_edit_entry.borrow_mut().dirty = true;
        display_entry(s, state_for_edit_entry.clone(), &entry_to_edit, true);

        s.pop_layer();

        if show_scroll_message {
            show_message(s, "Entry created successfully. It has been selected\n but you may need to scroll to it manually.");            
        }
    })
    .button("Insert Password", move |s: &mut Cursive| {
        generate_password(s, state_for_gen_pw.clone());
    })
    .button("Paste clipboard", move |s: &mut Cursive| {
        let pasted_txt: String;
        let paste_cmd: &String;

        {
            let app_state = &state_for_paste.borrow();
            paste_cmd = &app_state.paste_command;

            pasted_txt = match crate::clip::get_clipboard(&paste_cmd.as_str()) {
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
        if show_scroll_message_2 {
            show_message(s, "Entry created successfully. It has been selected\n but you may need to scroll to it manually.");            
        }  
    });                
    
    s.add_layer(res);
}

fn rename_entry(s: &mut Cursive, state_for_rename_entry: Rc<RefCell<AppState>>) {
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

        let old_entry_contents: Option<String>;
        old_entry_contents = state_for_rename_entry.borrow().store.get(&old_entry_name);

        let contents = match old_entry_contents {
            None =>  { show_message(s, "Unable to read old entry"); return },
            Some(s) => s
        };

        let new_entry_contents: Option<String>;
        new_entry_contents = state_for_rename_entry.borrow().store.get(&new_entry_name);

        match new_entry_contents {
            Some(_) => { show_message(s, "An entry with the new name already exists"); return },
            None => {
                state_for_rename_entry.borrow_mut().store.remove(&old_entry_name);
                state_for_rename_entry.borrow_mut().store.insert(&new_entry_name, &contents);
                state_for_rename_entry.borrow_mut().dirty = true;
                fill_tui(s, state_for_rename_entry.clone());
                s.pop_layer();
                display_entry(s, state_for_rename_entry.clone(), &new_entry_name, true);
                show_message(s, "Entry renamed successfully. The renamed entry has been selected\n but you may need to scroll to it manually.");
            }
        }
    })
    .button("Cancel", |s| { s.pop_layer(); });                
    
    s.add_layer(res);


}

static PW_EDIT1_CH: &str = "pwchedit1";
static PW_EDIT2_CH: &str = "pwchedit2";
static DLG_PW_CH: &str = "pwchangedlg";

fn change_password(s: &mut Cursive, state_for_pw_change: Rc<RefCell<AppState>>) {
    let res = Dialog::new()
        .title("Rustpwman change password")
        .padding_lrtb(2, 2, 1, 1)
        .content(
            LinearLayout::vertical()
            .child(TextView::new("Enter a new password.\n\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("New Password   : "))
                    .child(EditView::new()
                        .secret()
                        .with_name(PW_EDIT1_CH)
                        .fixed_width(PW_WIDTH))
            )
            .child(TextView::new("\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("Verify Password: "))
                    .child(EditView::new()
                        .secret()
                        .with_name(PW_EDIT2_CH)
                        .fixed_width(PW_WIDTH))
            )
        )
        .button("OK", move |s| {
            let pw1_text = match s.call_on_name("pwchedit1", |view: &mut EditView| {view.get_content()}) {
                Some(s) => s,
                None => { show_message(s, "Unable to read password"); return }
            };

            let pw2_text = match s.call_on_name("pwchedit2", |view: &mut EditView| {view.get_content()}) {
                Some(s) => s,
                None => { show_message(s, "Unable to read password"); return }
            };
            
            if pw1_text != pw2_text {
                show_pw_select_error(s, "Passwords not equal!", PW_EDIT1_CH, PW_EDIT2_CH, DLG_PW_CH);
                return;
            }

            if pw1_text.len() == 0 {
                show_pw_select_error(s, "New password is empty", PW_EDIT1_CH, PW_EDIT2_CH, DLG_PW_CH);
                return;
            }

            let new_pw: String = (&pw1_text).to_string();

            state_for_pw_change.borrow_mut().password = Some(new_pw);
            process_save_command(s, state_for_pw_change.clone());
            s.pop_layer();

            #[cfg(feature = "pwmanclient")]
            uncache_password(s, state_for_pw_change.clone());
        })
        .button("Cancel", |s| { s.pop_layer(); })
        .with_name(DLG_PW_CH);

    s.add_layer(res);
}

#[cfg(feature = "pwmanclient")]
fn cache_password(s: &mut Cursive, state_for_write_cache: Rc<RefCell<AppState>>) {
    let pw_option = state_for_write_cache.borrow().password.clone();
    let file_name = state_for_write_cache.borrow().file_name.clone();
    let password : String;
    let client: Box<dyn PWManClient>;

    if let Some(p) = pw_option {
        password = p;
    } else {
        show_message(s, "No password found in application state");
        return;
    }

    let c = make_pwman_client(file_name);
    if let Ok(cl) = c {
        client = cl;
    } else {
        show_message(s, "Unable to construct PWMAN client");
        return;
    }

    match client.set_password(&password) {
        Ok(_) => {
            show_message(s, "Password successfully cached");
            return;
        },
        Err(e) => {
            show_message(s, format!("Could not cache password: {}", e).as_str());
            return;
        }
    }
}

#[cfg(feature = "pwmanclient")]
fn uncache_password(s: &mut Cursive, state_for_write_cache: Rc<RefCell<AppState>>) {
    let file_name = state_for_write_cache.borrow().file_name.clone();
    let client: Box<dyn PWManClient>;

    let c = make_pwman_client(file_name);
    if let Ok(cl) = c {
        client = cl;
    } else {
        show_message(s, "Unable to construct PWMAN client");
        return;
    }

    match client.reset_password() {
        Ok(_) => {
            show_message(s, "Cache cleared");
            return;
        },
        Err(e) => {
            show_message(s, format!("Could not clear cache: {}", e).as_str());
            return;
        }
    }
}

#[cfg(not(feature = "pwmanclient"))]
fn cache_password(s: &mut Cursive, _state_for_write_cache: Rc<RefCell<AppState>>) {
    show_message(s, "Sorry this feature is not available in this build") 
}

#[cfg(not(feature = "pwmanclient"))]
fn uncache_password(s: &mut Cursive, _state_for_write_cache: Rc<RefCell<AppState>>) {
    show_message(s, "Sorry this feature is not available in this build") 
}

fn main_window(s: &mut Cursive, state: AppState, sndr: Rc<Sender<String>>) {
    let select_view = SelectView::new();
    let shared_state: Rc<RefCell<AppState>> = Rc::new(RefCell::new(state));

    let state_temp_add = shared_state.clone();
    let state_temp_save = shared_state.clone();
    let state_temp_print = shared_state.clone();
    let state_temp_del = shared_state.clone();
    let state_temp_pw = shared_state.clone();
    let state_temp_edit = shared_state.clone();
    let state_temp_load = shared_state.clone();
    let state_temp_clear = shared_state.clone();
    let state_temp_rename = shared_state.clone();
    let state_temp_write_chache = shared_state.clone();
    let state_temp_clear_chache = shared_state.clone();
    let state_temp_count = shared_state.clone();
    let sender = sndr.clone();
    let sender2 = sndr.clone();

    let state_for_callback = shared_state.clone();
    let state_for_fill_tui = shared_state.clone();

    let menu_bar = s.menubar();

    #[cfg(not(feature = "pwmanclient"))]
    let mut file_tree : Tree;

    #[cfg(feature = "pwmanclient")]
    let file_tree : Tree;

    file_tree = Tree::new()
        .leaf("Save File", move |s| { 
            process_save_command(s, state_temp_save.clone()); 
        })
        .delimiter()
        .leaf("Change password ...", move |s| {
            change_password(s, state_temp_pw.clone())
        })            
        .leaf("Cache password", move |s| { 
            cache_password(s, state_temp_write_chache.clone())  
        })
        .leaf("Clear cached password", move |s| { 
            uncache_password(s, state_temp_clear_chache.clone())  
        })
        .delimiter()
        .leaf("About ...", |s| {
            let msg_str = format!("\n   A primitive password manager\n\nWritten by Martin Grap in 2021-2023\n\n           Version {}", VERSION_STRING);
            show_message(s, &msg_str[..]);
        })
        .leaf("Count entries ...", move |s| {
            let num_entries = state_temp_count.borrow().store.len();
            let msg_str = format!("\nThere are {} entries", num_entries);
            show_message(s, &msg_str[..]);
        })            
        .delimiter()
        .leaf("Quit and print", move |s| {
            let key = match get_selected_entry_name(s) {
                Some(k) => k,
                None => { show_message(s, "Unable to read entry name"); return }
            };

            let value = match state_temp_print.borrow().store.get(&key) {
                Some(v) => v,
                None => { show_message(s, "Unable to read entry value"); return } 
            };

            let out_str = format!("-------- {} --------\n{}", key, value);

            pwman_quit(s, sender2.clone(), out_str, state_temp_print.borrow().dirty) 
        })            
        .leaf("Quit", move |s| pwman_quit(s, sender.clone(), String::from(""), shared_state.borrow().dirty )
    );

    // Ok this is really, really hacky but it works. I would have preferred to be able to simply exclude some lines from
    // compilation when constructing the file_tree but I came to the opinion that in Rust conditional compilation is tied to 
    // attributes which in turn does not seem to work when chaining values together as is done above.    
    #[cfg(not(feature = "pwmanclient"))]
    file_tree.remove(3);  // remove chache items when building without the pwmanclient feature

    #[cfg(not(feature = "pwmanclient"))]
    file_tree.remove(3);  // remove chache items when building without the pwmanclient feature

    menu_bar.add_subtree(
        "File", file_tree
        )
        .add_subtree(
            "Entry", Tree::new()
            .leaf("Edit Entry ...", move |s| {
                edit_entry(s, state_temp_edit.clone(), None)
            })        
            .leaf("Add Entry ...", move |s| {
                add_entry(s, state_temp_add.clone());
            })
            .leaf("Delete Entry ...", move |s| {
                delete_entry(s, state_temp_del.clone()); 
            }) 
            .leaf("Rename Entry ...", move |s| {
                rename_entry(s, state_temp_rename.clone()); 
            }) 
            .leaf("Clear Entry ...", move |s| {
                clear_entry(s, state_temp_clear.clone()); 
            })                    
            .leaf("Load Entry ...", move |s| {
                load_entry(s, state_temp_load.clone())  
            }));        

    s.set_autohide_menu(false);
    s.add_global_callback(Key::Esc, |s| s.select_menubar());
    
    let select_view_attributed = select_view
        .h_align(HAlign::Center)
        .on_select(move |s, item| {
            display_entry(s, state_for_callback.clone(), item, false)
        })
        .autojump()   
        .with_name(SELECT_VIEW)
        .fixed_width(40)
        .scrollable()
        .with_name(SCROLL_VIEW);

    let tui = LinearLayout::horizontal()
    .child(
        Panel::new(
            select_view_attributed)
        .title("Entries")
    )
    .child(
        LinearLayout::vertical()
        .child(Panel::new(          
            TextArea::new()
                .disabled()
                .content("")
                .with_name(TEXT_AREA_TITLE)
                .fixed_width(80)
                .fixed_height(1))
            .title("Name of selected entry")
        )
        .child(Panel::new(
            TextArea::new()
                .disabled()
                .content("")
                .with_name(TEXT_AREA_MAIN)
                .fixed_width(100)
                .min_height(40)
        )
        .title("Contents of entry")
        .with_name(PANEL_AREA_MAIN))      
    );
    
    s.add_layer(tui);
    fill_tui(s, state_for_fill_tui.clone());
}


fn show_pw_error(siv: &mut Cursive, msg: &str) {
    siv.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Ok", |s| {
                s.pop_layer();

                s.call_on_name("pwedit", |view: &mut EditView| {view.set_content(String::from(""))}).unwrap()(s);
                s.call_on_name("pwdialog", |view: &mut Dialog| {view.set_focus(DialogFocus::Content)});
            }),
    );
}

fn open_file(s: &mut Cursive, password: &String, state: AppState) -> Option<AppState> {
    let file_name = state.file_name.clone();
    let mut state = state;
    
    if !path_exists(&file_name) {
        match state.store.to_enc_file(&file_name, password) {
            Ok(_) => (),
            Err(_) => {
                show_message(s, &format!("Unable to initialize file\n\n{}", &file_name));
                return None;
            }
        }
    }

    match state.store.from_enc_file(&file_name, password) {
        Ok(_) => { },
        Err(e) => {
            show_pw_error(s, &format!("Unable to read file '{}'\n\nError: '{:?}'", file_name, e));
            return None;                
        }
    }

    state.password = Some(password.clone());

    return Some(state);
}

fn password_entry_dialog(sndr: Rc<Sender<String>>, ok_cb_with_state: Box<dyn Fn(&mut Cursive, &String)>) -> impl View {
    let sender = sndr.clone();

    let ok_cb = move |s: &mut Cursive| {
        let pw_text = match s.call_on_name("pwedit", |view: &mut EditView| {view.get_content()}) {
            Some(s) => s,
            None => { show_message(s, "Unable to read password"); return }
        };

        if let Some(err) = fcrypt::GcmContext::check_password(&pw_text) {
            show_message(s, &format!("Password incorrect: {:?}", err));
            return;        
        }        

        ok_cb_with_state(s, &pw_text);
    };

    let res = Dialog::new()
        .title("Rustpwman enter password")
        .padding_lrtb(2, 2, 1, 1)
        .content(
            LinearLayout::vertical()
            .child(TextView::new("Please enter password of data file.\n\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("Password: "))
                    .child(EditView::new()
                        .secret()
                        .with_name("pwedit")
                        .fixed_width(PW_WIDTH))
                    .with_name("pwlinear")
            )
        )
        .button("OK", ok_cb)
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from(""), false))
        .with_name("pwdialog");

    return res;
}

#[cfg(feature = "pwmanclient")]
fn password_read_from_pwman_dialog(sndr: Rc<Sender<String>>, password: String, client: Box<dyn PWManClient>, ok_cb_with_state: Box<dyn Fn(&mut Cursive, &String)>) -> Dialog {
    let sender = sndr.clone();
    let sender2 = sndr.clone();

    let ok_cb = move |s: &mut Cursive| {
        ok_cb_with_state(s, &password);
    };

    let res = Dialog::new()
        .title("Rustpwman confirm password")
        .padding_lrtb(2, 2, 1, 1)
        .content(
            LinearLayout::horizontal()
                .child(TextView::new("Password has been read from PWMAN.\n\n             Continue?\n"))                        
        )
        .button("OK", ok_cb)
        .button("Clear PW", move |s| {
            match client.reset_password() {
                Ok(_) => {
                    let sender3 = sender2.clone();
                    s.add_layer(
                        Dialog::text("Cached password has been cleared. Quitting now ...")
                            .title("Rustpwman")
                            .button("Ok", move |s| {
                                s.pop_layer();
                                pwman_quit(s, sender3.clone(), String::from(""), false)
                            }),
                    );                    
                },
                Err(e) => {
                    show_message(s, format!("{}", e).as_str());
                }
            }            
        })
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from(""), false));

    return res;
}

static PW_EDIT1: &str = "pwedit1";
static PW_EDIT2: &str = "pwedit2";
static DLG_INIT: &str = "pwinit";

fn verify_passwords(s: &mut Cursive, ok_cb: &Box<dyn Fn(&mut Cursive, &String)>) {
    verify_passwords_with_names(s, ok_cb, PW_EDIT1, PW_EDIT2, DLG_INIT);
}

fn show_pw_select_error(siv: &mut Cursive, msg: &str, edit1: &'static str, edit2: &'static str, dlg: &'static str) {
    siv.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Ok", |s| {
                s.pop_layer();
                s.call_on_name(edit1, |view: &mut EditView| {view.set_content(String::from(""))}).unwrap()(s);
                s.call_on_name(edit2, |view: &mut EditView| {view.set_content(String::from(""))}).unwrap()(s);
                s.call_on_name(dlg, |view: &mut Dialog| {view.set_focus(DialogFocus::Content)});
                match s.call_on_name(dlg, |view: &mut Dialog| {view.focus_view(&Name(edit1))}).unwrap() {
                    Ok(o) => {
                        match o {
                            EventResult::Ignored => (),
                            EventResult::Consumed(ocb) => {
                                match ocb {
                                    None => (),
                                    Some(cb) => cb(s)
                                }
                            }
                        }
                    },
                    Err(_) => ()
                }
            }),
    );
}

fn verify_passwords_with_names(s: &mut Cursive, ok_cb: &Box<dyn Fn(&mut Cursive, &String)>, edit1: &'static str, edit2: &'static str, dlg: &'static str) {
    let pw1_text = match s.call_on_name(edit1, |view: &mut EditView| {view.get_content()}) {
        Some(s) => s,
        None => { show_message(s, "Unable to read password"); return }
    };

    let pw2_text = match s.call_on_name(edit2, |view: &mut EditView| {view.get_content()}) {
        Some(s) => s,
        None => { show_message(s, "Unable to read password"); return }
    };

    if pw1_text != pw2_text {
        show_pw_select_error(s, "Passwords not equal!", edit1, edit2, dlg);
        return;
    }

    if pw1_text.len() == 0 {
        show_pw_select_error(s, "Password is empty!", edit1, edit2, dlg);
        return;
    }

    if let Some(err) = fcrypt::GcmContext::check_password(&pw1_text) {
        show_pw_select_error(s, &format!("Password incorrect: {:?}", err), edit1, edit2, dlg);
        return;        
    }

    ok_cb(s, &pw2_text);
}

fn file_init_dialog(sndr: Rc<Sender<String>>, ok_cb: Box<dyn Fn(&mut Cursive, &String)>) -> impl View {
    let sender = sndr.clone();
    
    let verify = move |s: &mut Cursive| {
        verify_passwords(s, &ok_cb);
    };

    let res = Dialog::new()
        .title("Rustpwman create new file")
        .padding_lrtb(2, 2, 1, 1)
        .content(
            LinearLayout::vertical()
            .child(TextView::new("File not found! Enter a new password\nto create a new empty data file.\n\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("New Password   : "))
                    .child(EditView::new()
                        .secret()
                        .with_name(PW_EDIT1)
                        .fixed_width(PW_WIDTH))
                    .with_name("firstpw")
            )
            .child(TextView::new("\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("Verify Password: "))
                    .child(EditView::new()
                        .secret()
                        .with_name(PW_EDIT2)
                        .fixed_width(PW_WIDTH))
            )
        )
        .button("OK", verify)
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from(""), false))
        .with_name(DLG_INIT);

    return res;
}


