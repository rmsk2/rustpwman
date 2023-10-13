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
mod tuiundo;
pub mod tuimain;

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
use cursive::views::{Dialog, LinearLayout, SelectView, TextArea, Panel, NamedView, ScrollView, ResizedView};
use cursive::Cursive;
use cursive::menu::Tree;
use cursive::align::HAlign;
use cursive::event::Key;
use cursive::reexports::enumset;
use cursive::theme;
use cursive::theme::{ColorType, Effect, Color, PaletteColor};

use std::rc::Rc;
use std::cell::RefCell;
use std::sync::mpsc::Sender;

use std::fs;
use std::collections::HashMap;

use crate::pwgen::GenerationStrategy;
use crate::pwgen::PasswordGenerator;
use crate::jots;

pub fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

pub struct AppState {
    store: jots::Jots,
    password: Option<String>,
    file_name: String,
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

fn do_quit(s: &mut Cursive, sender: Rc<Sender<String>>, message: String) {
    match sender.send(message) {
        Ok(_) => (),
        Err(_) => ()
    };
    
    s.quit();
}

fn pwman_quit_with_state(s: &mut Cursive, sender: Rc<Sender<String>>, message: String, dirty_bit: bool, app_state: Option<Rc<RefCell<AppState>>>) {
    let msg = message.clone();
    let msg2 = message.clone();
    let sndr = sender.clone();
    let sndr2 = sender.clone();

    if dirty_bit {
        s.add_layer(
            Dialog::text("There are unsaved changes. Continue anyway?")
                .title("Rustpwman")
                .button("Yes", move |s: &mut Cursive| {
                    s.pop_layer();
                    do_quit(s, sndr.clone(), msg.clone());
                })
                .button("No", move |s| {
                    s.pop_layer();
                    
                    match &app_state {
                        None => {},
                        Some(state) => {
                            ask_for_save(s, sndr2.clone(), msg2.clone(), state.clone());
                        }
                    }
                })           
        );
    } else {
        do_quit(s, sender, message);
    }
} 

fn ask_for_save(s: &mut Cursive, sender: Rc<Sender<String>>, message: String, app_state: Rc<RefCell<AppState>>) {
    s.add_layer(
        Dialog::text("Save file and quit?")
            .title("Rustpwman")
            .button("Yes", move |s: &mut Cursive| {
                s.pop_layer(); 
                save::file(s, app_state.clone());

                if !app_state.borrow().store.is_dirty() {
                    do_quit(s, sender.clone(), message.clone());
                }
            })
            .button("No", |s| {
                s.pop_layer();
            })
        )           
}

fn pwman_quit(s: &mut Cursive, sender: Rc<Sender<String>>, message: String)
{
    pwman_quit_with_state(s, sender, message, false, None);
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

fn redraw_tui(siv: &mut Cursive, state: Rc<RefCell<AppState>>) {
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

fn visualize_if_modified(siv: &mut Cursive, state: Rc<RefCell<AppState>>) {
    if state.borrow().store.is_dirty() {
        siv.call_on_name("EntrySelectPanel", |view: &mut Panel<NamedView<ScrollView<ResizedView<NamedView<SelectView>>>>>| { view.set_title("Entries *"); } );
    } else {
        siv.call_on_name("EntrySelectPanel", |view: &mut Panel<NamedView<ScrollView<ResizedView<NamedView<SelectView>>>>>| { view.set_title("Entries"); } );
    }
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
    let state_temp_quit = shared_state.clone();
    let state_temp_quit_print = shared_state.clone();
    let sender = sndr.clone();
    let sender2 = sndr.clone();

    let state_for_callback = shared_state.clone();
    let state_for_fill_tui = shared_state.clone();
    let state_for_undo = shared_state.clone();

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
            cache::password(s, state_temp_write_chache.clone())  
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
        .leaf("Undo last change ...", move |s| {
            tuiundo::undo(s, state_for_undo.clone());
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

            pwman_quit_with_state(s, sender2.clone(), out_str, state_temp_print.borrow().store.is_dirty(), Some(state_temp_quit_print.clone())) 
        })            
        .leaf("Quit", move |s| pwman_quit_with_state(s, sender.clone(), String::from(""), shared_state.borrow().store.is_dirty(), Some(state_temp_quit.clone()) )
    );

    // Ok this is really, really hacky but it works. I would have preferred to be able to simply exclude some lines from
    // compilation when constructing the file_tree but I came to the opinion that in Rust conditional compilation is tied to 
    // attributes which in turn does not seem to work when chaining values together as is done above.    
    #[cfg(not(feature = "pwmanclient"))]
    file_tree.remove(3);  // remove cache item when building without the pwmanclient feature

    #[cfg(not(feature = "pwmanclient"))]
    file_tree.remove(3);  // remove cache clear item when building without the pwmanclient feature

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

    let entry_select_panel = Panel::new(select_view_attributed)
        .title("Entries")
        .with_name("EntrySelectPanel");


    let tui = LinearLayout::horizontal()
    .child(entry_select_panel)
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
    redraw_tui(s, state_for_fill_tui.clone());
}





