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
mod copy;
mod open;
mod info;
mod export;
mod queue;
pub mod tuimain;

pub const PW_MAX_SEC_LEVEL: usize = 32;

pub const PW_SEC_LEVEL: usize = 9;
const SCROLL_VIEW: &str = "scrollview";
const SELECT_VIEW: &str = "entrylist";
const PANEL_AREA_MAIN: &str = "entrytitle";
const TEXT_AREA_TITLE: &str = "texttitle";
const TEXT_AREA_MAIN: &str = "entrytext";
const PW_WIDTH: usize = 35;

pub const DEFAULT_PASTE_CMD: &str = "xsel -ob";
pub const DEFAULT_COPY_CMD: &str = "xsel -ib";

use crate::persist::SendSyncPersister;
use cursive::theme::ColorStyle;
use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, SelectView, TextArea, Panel, NamedView, ScrollView, ResizedView, OnEventView};
use cursive::Cursive;
use cursive::menu::Tree;
use cursive::align::HAlign;
use cursive::event::Key;
use cursive::theme;
use cursive::theme::Effects;
use cursive::theme::Effect;
use std::sync::{Arc, Mutex};

use std::sync::mpsc::Sender;
use std::io::{Error, ErrorKind};

use crate::pwgen::GenerationStrategy;
use crate::jots;


pub struct AppState {
    store: jots::Jots,
    password: Option<String>,
    store_id: String,
    default_security_level: usize,
    default_generator: GenerationStrategy,
    paste_command: String,
    copy_command: String,
    persister: SendSyncPersister, 
    last_custom_selection: String,
    pw_is_chached: bool,
    entry_queue: Vec<String>,
}

impl AppState {
    pub fn new(s: jots::Jots, f_name: &String, default_sec: usize, default_gen: GenerationStrategy, 
               paste_cmd: &String, copy_cmd: &String, p: SendSyncPersister, is_pw_cached: bool) -> Self {
        return AppState {
            store: s,
            password: None,
            store_id: f_name.clone(),
            default_security_level: default_sec,
            default_generator: default_gen,
            paste_command: paste_cmd.clone(),
            copy_command: copy_cmd.clone(),
            persister: p,
            last_custom_selection: String::from(""),
            pw_is_chached: is_pw_cached,
            entry_queue: Vec::new()
        }
    }

    pub fn get_default_bits(&self) -> usize {
        return self.default_security_level;
    }

    pub fn persist_store(&mut self) -> std::io::Result<()> {
        let pw = match &self.password {
            Some(p) => p,
            None => {
                return Err(Error::new(ErrorKind::Other, format!("No password available, unable to persist store '{}'", &self.store_id)));
            }
        };
        
        return self.store.persist(&mut self.persister, pw.as_str());
    }   
}

fn do_quit(s: &mut Cursive, sender: Arc<Sender<String>>, message: String) {
    match sender.send(message) {
        Ok(_) => (),
        Err(_) => ()
    };
    
    s.quit();
}

/*fn process_event_result(s: &mut Cursive, call_res:Option<EventResult>) {
    match call_res {
        None => (),
        Some(event) => match event {
            Ignored => (),
            Consumed(opt_callback) => {
                match opt_callback {
                    None => (),
                    Some(cb) => cb(s)
                }
            }
        }
    }
}*/

fn pwman_quit_with_state(s: &mut Cursive, sender: Arc<Sender<String>>, message: String, dirty_bit: bool, app_state: Option<Arc<Mutex<AppState>>>) {
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

fn ask_for_save(s: &mut Cursive, sender: Arc<Sender<String>>, message: String, app_state: Arc<Mutex<AppState>>) {
    s.add_layer(
        Dialog::text("Save file and quit?")
            .title("Rustpwman")
            .button("Yes", move |s: &mut Cursive| {
                s.pop_layer(); 
                save::storage(s, app_state.clone());

                let is_dirty = app_state.lock().unwrap().store.is_dirty();

                if !is_dirty {
                    do_quit(s, sender.clone(), message.clone());
                }
            })
            .button("No", |s| {
                s.pop_layer();
            })
        )           
}

fn pwman_quit(s: &mut Cursive, sender: Arc<Sender<String>>, message: String)
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

fn display_entry(siv: &mut Cursive, state: Arc<Mutex<AppState>>, entry_name: &String, do_select: bool) {
    if entry_name == "" {
        return;
    }

    let entry_text: String;
    let pos: usize;

    {
        let h = state.lock().unwrap();
        let store = &(*h).store;

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

fn redraw_tui(siv: &mut Cursive, state: Arc<Mutex<AppState>>) {
    let mut count = 0;
    let mut initial_entry = String::from("");

    siv.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.clear(); } );
    siv.call_on_name(TEXT_AREA_MAIN, |view: &mut TextArea| { view.set_content(""); });
    siv.call_on_name(TEXT_AREA_TITLE, |view: &mut TextArea| { view.set_content(""); });

    {
        let h = state.lock().unwrap();
        let store = &(*h).store;

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
    let mut eff_simple = Effects::empty();
    eff_simple.insert(Effect::Simple);

    let mut eff_reverse = Effects::empty();
    eff_reverse.insert(Effect::Reverse);

    let reverse_style = theme::Style {
        effects: eff_reverse,
        color: ColorStyle::secondary()
    };

    let danger_style = theme::Style {
        effects: eff_simple,
        color: ColorStyle::highlight()
    };

    return (danger_style, reverse_style);    
}

fn visualize_if_modified(siv: &mut Cursive, state: Arc<Mutex<AppState>>) {
    let is_dirty = state.lock().unwrap().store.is_dirty();

    if is_dirty {
        siv.call_on_name("EntrySelectPanel", |view: &mut Panel<NamedView<ScrollView<ResizedView<OnEventView<NamedView<SelectView>>>>>>| { view.set_title("Entries *"); } );
    } else {
        siv.call_on_name("EntrySelectPanel", |view: &mut Panel<NamedView<ScrollView<ResizedView<OnEventView<NamedView<SelectView>>>>>>| { view.set_title("Entries"); } );
    }
}

fn quit_and_print(s: &mut Cursive, state: Arc<Mutex<AppState>>, sndr: Arc<Sender<String>>) {
    let key = match get_selected_entry_name(s) {
        Some(k) => k,
        None => { show_message(s, "Unable to read entry name"); return }
    };

    let dirty_flag: bool;
    let mut out_str = queue::get_entries(state.clone());
    
    // Create artificial scope to ensure unlock of Mutex
    {
        let h = state.lock().unwrap();
        let store = &(*h).store;

        let value = match store.get(&key) {
            Some(v) => v,
            None => { show_message(s, "Unable to read entry value"); return } 
        };

        out_str.push_str(format_pw_entry(&key, &value).as_str());
        dirty_flag = store.is_dirty();
    }

    pwman_quit_with_state(s, sndr.clone(), out_str, dirty_flag, Some(state.clone()))
}

fn format_pw_entry(key: &String, value: &String) -> String {
    return format!("-------- {} --------\n{}", key, value);
}

#[derive(Clone)]
struct AppCtx {
    state: Arc<Mutex<AppState>>,
    sndr: Arc<Sender<String>>
}

impl AppCtx {
    fn new(shared_state: Arc<Mutex<AppState>>, sndr: Arc<Sender<String>>) -> AppCtx {
        let res = AppCtx {
            state: shared_state.clone(),
            sndr: sndr.clone()
        };

        return res;
    }

    fn call_save(&self, s: &mut Cursive) {
        save::storage(s, self.state.clone()); 
    }

    fn pw_change(&self, s: &mut Cursive) {
        pw::change(s, self.state.clone()); 
    }

    fn quit_and_print(&self, s: &mut Cursive) {
        quit_and_print(s, self.state.clone(), self.sndr.clone());
    }
}

fn main_window(s: &mut Cursive, shared_state: Arc<Mutex<AppState>>, sndr: Arc<Sender<String>>) {
    let select_view = SelectView::new();
    let h = AppCtx::new(shared_state.clone(), sndr.clone());
    let h2 = h.clone();
    let h3 = h.clone();


    let state_temp_add = shared_state.clone();
    let state_temp_del = shared_state.clone();
    let state_temp_edit = shared_state.clone();
    let state_temp_load = shared_state.clone();
    let state_temp_clear = shared_state.clone();
    let state_temp_rename = shared_state.clone();
    let state_temp_write_chache = shared_state.clone();
    let state_temp_clear_chache = shared_state.clone();
    let state_temp_info = shared_state.clone();
    let state_temp_quit = shared_state.clone();
    let state_temp_quit_print2 = shared_state.clone();
    let sender = sndr.clone();
    let sender3 = sndr.clone();
    let sender4 = sndr.clone();
    let state_temp_copy = shared_state.clone();
    let state_temp_copy2 = shared_state.clone();
    let state_temp_q_add = shared_state.clone();
    let state_temp_q_add2 = shared_state.clone();
    let state_temp_q_clear = shared_state.clone();
    let state_temp_q_show = shared_state.clone();
    let state_temp_global_quit = shared_state.clone();

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
            h.call_save(s);
        })
        .delimiter()
        .leaf("Change password ...", move |s| {
            h2.pw_change(s);
        })            
        .leaf("Cache password", move |s| { 
            cache::password(s, state_temp_write_chache.clone())  
        })
        .leaf("Clear cached password", move |s| { 
            cache::uncache_password(s, state_temp_clear_chache.clone())  
        })
        .delimiter()
        .leaf("About ...", |s| {
            info::about(s)
        })
        .leaf("Info ...", move |s| {
            info::show(s, state_temp_info.clone());
        })   
        .leaf("Undo changes ...", move |s| {
            tuiundo::undo(s, state_for_undo.clone());
        })                    
        .delimiter()
        .leaf("Quit and print        F4", move |s| {
            h3.quit_and_print(s);
        })            
        .leaf("Quit                  F3", move |s| pwman_quit_with_state(s, sender.clone(), String::from(""), shared_state.lock().unwrap().store.is_dirty(), Some(state_temp_quit.clone()) )
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
            .leaf("Copy to clipboard ... F2", move |s| {
                copy::entry(s, state_temp_copy.clone(), true)
            })
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
            })
        )
        .add_subtree("Queue", 
            Tree::new()
            .leaf("Add to queue   F1", move |s| {
                queue::add(s, state_temp_q_add.clone());
            })
            .leaf("Show queue ...", move |s| {
                queue::show(s, state_temp_q_show.clone());
            })
            .delimiter()        
            .leaf("Clear queue", move |_s| {
                queue::clear(state_temp_q_clear.clone());
            })            
        );        

    s.set_autohide_menu(false);

    s.add_global_callback(Key::Esc, |s| s.select_menubar());
    s.add_global_callback(Key::F3, move |s| pwman_quit_with_state(s, sender3.clone(), String::from(""), state_temp_global_quit.lock().unwrap().store.is_dirty(), Some(state_temp_global_quit.clone())));
    s.add_global_callback(Key::F4, move |s| quit_and_print(s, state_temp_quit_print2.clone(), sender4.clone()));
    
    let mut event_wrapped_select_view = OnEventView::new(
        select_view
        .h_align(HAlign::Center)
        .on_select(move |s, item| {
            display_entry(s, state_for_callback.clone(), item, false)
        })
        .autojump()
        .with_name(SELECT_VIEW)
    );

    event_wrapped_select_view.set_on_event(Key::F1,  move |s| {
        queue::add(s, state_temp_q_add2.clone())
    });

    event_wrapped_select_view.set_on_event(Key::F2, move |s| {
        copy::entry(s, state_temp_copy2.clone(), false)
    });    

    let select_view_scrollable = event_wrapped_select_view
        .fixed_width(40)
        .scrollable()
        .with_name(SCROLL_VIEW);

    let entry_select_panel = Panel::new(select_view_scrollable)
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
                .min_height(42)
                .scrollable()
        )
        .title("Contents of entry")
        .with_name(PANEL_AREA_MAIN))      
    );
    
    s.add_layer(tui);
    redraw_tui(s, state_for_fill_tui.clone());
}





