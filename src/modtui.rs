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

mod cache;
mod pwgenerate;
mod load;
mod rename;
mod delete;
mod save;
mod add;
mod clear;
mod edit;
mod pw;
mod pwentry;
mod init;

pub const PW_MAX_SEC_LEVEL: usize = 24;

pub const PW_SEC_LEVEL: usize = 9;
const SCROLL_VIEW: &str = "scrollview";
const SELECT_VIEW: &str = "entrylist";
const PANEL_AREA_MAIN: &str = "entrytitle";
const TEXT_AREA_TITLE: &str = "texttitle";
const TEXT_AREA_MAIN: &str = "entrytext";
const PW_WIDTH: usize = 35;

pub const DEFAULT_PASTE_CMD: &str = "xsel -ob";

use crate::VERSION_STRING;
use cursive::theme::ColorStyle;
use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, EditView, SelectView, TextArea, Panel, DialogFocus};
use cursive::Cursive;
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

use crate::pwgen;
use crate::pwgen::GenerationStrategy;
use crate::pwgen::PasswordGenerator;
use crate::fcrypt::KeyDeriver;
use crate::fcrypt;
use crate::jots;

pub fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
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

        match cache::make_pwman_client(file_name_for_uds_client.clone()) {
            Ok(c) => {
                match c.get_password() {
                    Ok(password) => {
                        let d = cache::password_read_from_pwman_dialog(sender.clone(), password.clone(), c, pw_callback);
                        siv.add_layer(d);
                    },
                    Err(_) => {                        
                        let d = pwentry::dialog(sender.clone(), pw_callback);
                        siv.add_layer(d);        
                    }
                }
            }
            Err(_) => {                
                let d = pwentry::dialog(sender.clone(), pw_callback);
                siv.add_layer(d);
            }
        };
    } else {
        let d = init::dialog(sender.clone(), pw_callback);
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

    if message != "" {
        println!("{}", message);
    }
    
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
            save::file(s, state_temp_save.clone()); 
        })
        .delimiter()
        .leaf("Change password ...", move |s| {
            pw::change(s, state_temp_pw.clone())
        })            
        .leaf("Cache password", move |s| { 
            cache::cache_password(s, state_temp_write_chache.clone())  
        })
        .leaf("Clear cached password", move |s| { 
            cache::uncache_password(s, state_temp_clear_chache.clone())  
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
                edit::entry(s, state_temp_edit.clone(), None)
            })        
            .leaf("Add Entry ...", move |s| {
                add::entry(s, state_temp_add.clone());
            })
            .leaf("Delete Entry ...", move |s| {
                delete::entry(s, state_temp_del.clone()); 
            }) 
            .leaf("Rename Entry ...", move |s| {
                rename::entry(s, state_temp_rename.clone()); 
            }) 
            .leaf("Clear Entry ...", move |s| {
                clear::entry(s, state_temp_clear.clone()); 
            })                    
            .leaf("Load Entry ...", move |s| {
                load::entry(s, state_temp_load.clone())  
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




