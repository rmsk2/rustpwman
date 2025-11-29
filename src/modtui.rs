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

#[cfg(feature = "pwmanclient")]
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
#[cfg(feature = "qrcode")]
mod qrcode;
pub mod tuimain;
pub mod tuitheme;

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

pub type FormatterFunc = fn(&String, &String) -> String;
static DEFAULT_FORMATTER: FormatterFunc = format_pw_entry;

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

#[allow(dead_code)]
pub struct AppState {
    store: jots::Jots,
    password: Option<String>,
    store_id: String,
    default_security_level: usize,
    default_generator: GenerationStrategy,
    paste_command: String,
    copy_command: String,
    viewer_prefix: Option<String>,
    persister: SendSyncPersister,
    last_custom_selection: String,
    pw_is_chached: bool,
    entry_queue: Vec<String>,
}

impl AppState {
    pub fn new(s: jots::Jots, f_name: &String, default_sec: usize, default_gen: GenerationStrategy,
               paste_cmd: &String, copy_cmd: &String, p: SendSyncPersister, is_pw_cached: bool, qr_viewer: &Option<String>) -> Self {
        return AppState {
            store: s,
            password: None,
            store_id: f_name.clone(),
            default_security_level: default_sec,
            default_generator: default_gen,
            paste_command: paste_cmd.clone(),
            copy_command: copy_cmd.clone(),
            viewer_prefix: qr_viewer.clone(),
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
    let mut out_str = queue::get_entries(state.clone(), DEFAULT_FORMATTER);

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

fn copy_pw_entry_contents(_key: &String, value: &String) -> String {
    return value.clone();
}

fn quit_without_print(s :&mut Cursive, state: Arc<Mutex<AppState>>, sndr: Arc<Sender<String>>) {
    let is_dirty = state.lock().unwrap().store.is_dirty();

    pwman_quit_with_state(s, sndr.clone(), String::from(""), is_dirty, Some(state.clone()))
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
}

fn wrapper(ctx: AppCtx, f: fn(&mut Cursive, state: Arc<Mutex<AppState>>)) -> impl Fn(&mut Cursive) {
    return move |s| {
        f(s, ctx.state.clone());
    };
}

fn wrapper2(ctx: AppCtx, f: fn(&mut Cursive, state: Arc<Mutex<AppState>>, sndr: Arc<Sender<String>>)) -> impl Fn(&mut Cursive) {
    return move |s| {
        f(s, ctx.state.clone(), ctx.sndr.clone());
    };
}

fn wrapper3<T : Clone>(ctx: AppCtx, f: fn(&mut Cursive, state: Arc<Mutex<AppState>>, v: T), val: T) -> impl Fn(&mut Cursive) {
    return move |s| {
        f(s, ctx.state.clone(), val.clone());
    };
}

fn wrapper4<T : Clone, U: Clone>(ctx: AppCtx, f: fn(&mut Cursive, state: Arc<Mutex<AppState>>, v: T, u: U), val: T, val2: U) -> impl Fn(&mut Cursive) {
    return move |s| {
        f(s, ctx.state.clone(), val.clone(), val2.clone());
    };
}

fn build_entry_select_panel(ctx: &AppCtx) -> NamedView<Panel<NamedView<ScrollView<ResizedView<OnEventView<NamedView<SelectView>>>>>>> {
    let select_view = SelectView::new();
    let shared_state = ctx.state.clone();

    let mut event_wrapped_select_view = OnEventView::new(
        select_view
        .h_align(HAlign::Center)
        .on_select(move |s, item| {
            display_entry(s, shared_state.clone(), item, false)
        })
        .autojump()
        .with_name(SELECT_VIEW)
    );

    event_wrapped_select_view.set_on_event(Key::F1, wrapper(ctx.clone(), queue::add));
    event_wrapped_select_view.set_on_event(Key::F2, wrapper4(ctx.clone(), copy::entry, false, DEFAULT_FORMATTER));
    event_wrapped_select_view.set_on_event(Key::F5, wrapper3(ctx.clone(), copy::contents, false));

    let select_view_scrollable = event_wrapped_select_view
        .fixed_width(40)
        .scrollable()
        .with_name(SCROLL_VIEW);

    let entry_select_panel = Panel::new(select_view_scrollable)
        .title("Entries")
        .with_name("EntrySelectPanel");

    return entry_select_panel;
}


fn main_window(s: &mut Cursive, shared_state: Arc<Mutex<AppState>>, sndr: Arc<Sender<String>>) {
    let ctx = AppCtx::new(shared_state.clone(), sndr.clone());
    let state_for_fill_tui = shared_state.clone();

    let mut file_tree : Tree;
    file_tree = Tree::new();
    file_tree.add_leaf("Save File", wrapper(ctx.clone(), save::storage));
    file_tree.add_delimiter();
    file_tree.add_leaf("Change password ...", wrapper(ctx.clone(), pw::change));
    #[cfg(feature = "pwmanclient")]
    file_tree.add_leaf("Cache password", wrapper(ctx.clone(), cache::password));
    #[cfg(feature = "pwmanclient")]
    file_tree.add_leaf("Clear cached password", wrapper(ctx.clone(), cache::uncache_password));
    file_tree.add_delimiter();
    file_tree.add_leaf("About ...", info::about);
    file_tree.add_leaf("Info ...", wrapper(ctx.clone(), info::show));
    file_tree.add_leaf("Undo changes ...", wrapper(ctx.clone(), tuiundo::undo));
    file_tree.add_delimiter();
    file_tree.add_leaf("Quit and print        F4", wrapper2(ctx.clone(), quit_and_print));
    file_tree.add_leaf("Quit                  F3", wrapper2(ctx.clone(), quit_without_print)
    );

    let mut entry_tree = Tree::new();
    entry_tree.add_leaf("Copy to clipboard ... F2", wrapper4(ctx.clone(), copy::entry, true, DEFAULT_FORMATTER));
    entry_tree.add_leaf("Copy contents ...     F5", wrapper3(ctx.clone(), copy::contents, true));
    entry_tree.add_leaf("Edit Entry ...", wrapper3(ctx.clone(), edit::entry, None));
    entry_tree.add_leaf("Add Entry ...", wrapper(ctx.clone(), add::entry));
    entry_tree.add_leaf("Delete Entry ...", wrapper(ctx.clone(), delete::entry));
    entry_tree.add_leaf("Rename Entry ...", wrapper(ctx.clone(), rename::entry));
    entry_tree.add_leaf("Clear Entry ...", wrapper(ctx.clone(), clear::entry));
    entry_tree.add_leaf("Load Entry ...", wrapper(ctx.clone(), load::entry));

    #[cfg(feature = "qrcode")]
    entry_tree.add_leaf("To QR-Code ...", wrapper(ctx.clone(), qrcode::create));

    s.menubar()
        .add_subtree("File", file_tree)
        .add_subtree("Entry", entry_tree)
        .add_subtree("Queue",
            Tree::new()
            .leaf("Add to queue   F1", wrapper(ctx.clone(), queue::add))
            .leaf("Show queue ...", wrapper(ctx.clone(), queue::show))
            .delimiter()
            .leaf("Clear queue", wrapper(ctx.clone(), queue::clear))
        );

    s.set_autohide_menu(false);

    s.add_global_callback(Key::Esc, |s| s.select_menubar());
    s.add_global_callback(Key::F3, wrapper2(ctx.clone(), quit_without_print));
    s.add_global_callback(Key::F4, wrapper2(ctx.clone(), quit_and_print));


    let tui = LinearLayout::horizontal()
    .child(build_entry_select_panel(&ctx))
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





