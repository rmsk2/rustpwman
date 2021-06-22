use std::env;

mod tests;
mod fcrypt;
mod jots;

const PW_WIDTH: usize = 35;
const EDIT_NAME: &str = "nameedit";

use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, TextView, EditView, SelectView, TextArea, Panel};
use cursive::Cursive;
use cursive::menu::MenuTree;
use cursive::align::HAlign;

use std::rc::Rc;
use std::cell::RefCell;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
//use std::thread;

use std::fs;

pub fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

pub struct AppState {
    store: jots::Jots,
    password: Option<String>,
    file_name: String,
}

impl AppState {
    fn new(s: jots::Jots, f_name: &String) -> Self {
        return AppState {
            store: s,
            password: None,
            file_name: f_name.clone()        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() < 1 {
        println!("Usage: rustpwman <encrypted data file>");
        return;
    }

    let (tx, rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    let data_file_name = &args[0].clone();
    let capture_file_name = data_file_name.clone();
    let mut siv = cursive::default();
    let sender = Rc::new(tx);
    let sender_main = sender.clone();

    let pw_callback = Box::new(move |s: &mut Cursive, password: &String| {
        let jots_store = jots::Jots::new();
        let f_name = capture_file_name.clone();
        let state = AppState::new(jots_store, &f_name);

        if let Some(state_after_open) = open_file(s, password, state) {
            main_window(s, state_after_open, sender_main.clone());
        }
    });

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

fn pwman_quit<T: Sync>(s: &mut Cursive, sender: Rc<Sender<T>>, message: T)
{
    match sender.send(message) {
        Ok(_) => (),
        Err(_) => ()
    };
    s.quit();
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

fn fill_tui(siv: &mut Cursive, state: Rc<RefCell<AppState>>, name_select: &str, name_area: &str) {
    let mut count = 0;
    let mut initial_text = String::from("");

    siv.call_on_name(name_select, |view: &mut SelectView| { view.clear(); } );

    let store = &state.borrow().store;

    for i in store {
        if count == 0 {
            initial_text = match store.get(i) {
                Some(s) => s,
                None => { panic!("This should not have happened"); }
            }
        }

        siv.call_on_name(name_select, |view: &mut SelectView| { view.add_item(i.clone(), i.clone()); } );

        count += 1;
    }

    siv.call_on_name(name_area, |view: &mut TextArea| { view.set_content(initial_text); });
}

fn get_selected_entry_name(s: &mut Cursive) -> Option<String> {
    let id_opt = match s.call_on_name("entrylist", |view: &mut SelectView| { view.selected_id() }) {
        Some(i) => i,
        None => None
    };

    if let Some(id) = id_opt {
        let help = s.call_on_name("entrylist", |view: &mut SelectView| -> Option<String> { 
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

    let item = match get_selected_entry_name(s) {
        Some(k) => k,
        _ => { show_message(s, "Unable to read entry"); return; }
    };

    let text_val_opt = s.call_on_name("entrytext", |view: &mut TextArea| -> String { String::from(view.get_content()) });  
    let text_val = match text_val_opt {
        Some(st) => st,
        None => { show_message(s, "Unable to read entry"); return; }
    };

    state_temp_save.borrow_mut().store.insert(&item, &text_val);
    let file_name = state_temp_save.borrow().file_name.clone();

    match state_temp_save.borrow().store.to_enc_file(&file_name, &password) {
        Err(e) => { show_message(s, &format!("Unable to save: {:?}", e)); return; }
        _ => ()
    };
}

fn delete_entry(s: &mut Cursive, state_temp_del: Rc<RefCell<AppState>>) {
    match get_selected_entry_name(s) {
        Some(name) => {
            state_temp_del.borrow_mut().store.remove(&name);
            fill_tui(s, state_temp_del.clone(), "entrylist", "entrytext");
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
            Some(s) => s.clone(),
            None => { show_message(s, "Unable to read new entry"); return }
        }; 

        let old_entry: Option<String>;

        {
            old_entry = state_for_add_entry.borrow().store.get(&entry_name);
        }

        match old_entry {
            Some(_) => { show_message(s, "Entry already exists"); return },
            None => {
                let new_text = String::from("New entry");
                state_for_add_entry.borrow_mut().store.insert(&entry_name, &new_text);
                s.pop_layer();
                fill_tui(s, state_for_add_entry.clone(), "entrylist", "entrytext");                            
            }
        }
    })
    .button("Cancel", |s| { s.pop_layer(); });                
    
    s.add_layer(res);
}

fn main_window(s: &mut Cursive, state: AppState, sndr: Rc<Sender<String>>) {
    let select_view = SelectView::new();
    let shared_state: Rc<RefCell<AppState>> = Rc::new(RefCell::new(state));

    let state_temp_add = shared_state.clone();
    let state_temp_save = shared_state.clone();
    let state_temp_print = shared_state.clone();
    let state_temp_del = shared_state.clone();
    let sender = sndr.clone();
    let sender2 = sndr.clone();

    s.menubar()    
    .add_subtree(
        "File", MenuTree::new()
            .leaf("Add Entry", move |s| {
                add_entry(s, state_temp_add.clone());
            })
            .leaf("Delete Entry", move |s| {
                delete_entry(s, state_temp_del.clone()); 
            })
            .delimiter()
            .leaf("Save File", move |s| { process_save_command(s, state_temp_save.clone()); })
            .leaf("Change password", |_s| {})
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

                pwman_quit(s, sender2.clone(), value) 
            })            
            .leaf("Quit", move |s| pwman_quit(s, sender.clone(), String::from("")) ));

    s.set_autohide_menu(false);

    let state_for_callback = shared_state.clone();
    
    let select_view_attributed = select_view
        .h_align(HAlign::Center)
        .on_select(move |s, item| {
            let entry_text = match state_for_callback.borrow().store.get(item) {
                Some(s) => s,
                None => {
                    show_message(s, "Unable to read password entry"); return;
                }
            };
            s.call_on_name("entrytext", |view: &mut TextArea| { view.set_content(entry_text); });
        })   
        .with_name("entrylist")
        .fixed_width(40)
        .scrollable(); 

    let tui = LinearLayout::horizontal()
    .child(
        Panel::new(
            select_view_attributed)
        .title("Entries")
    )
    .child(
        Panel::new(
            TextArea::new()
                .content("")
                .with_name("entrytext")
                .fixed_width(100)
                .min_height(40)
        )
        .title("Contents of entry")
    );
    
    s.add_layer(tui);
    fill_tui(s, shared_state.clone(), "entrylist", "entrytext");
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
        Err(_) => {
            show_message(s, &format!("Unable to read file\n\n{}\n\nWrong password?", file_name));
            return None;                
        }
    }

    s.pop_layer();
    state.password = Some(password.clone());

    return Some(state);
}

fn password_entry_dialog(sndr: Rc<Sender<String>>, ok_cb_with_state: Box<dyn Fn(&mut Cursive, &String)>) -> Dialog {
    let sender = sndr.clone();

    let ok_cb = move |s: &mut Cursive| {
        let pw_text = match s.call_on_name("pwedit", |view: &mut EditView| {view.get_content()}) {
            Some(s) => s,
            None => { show_message(s, "Unable to read password"); return }
        };

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
            )
        )
        .button("OK", ok_cb)
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from("")));

    return res;
}

fn verify_passwords(s: &mut Cursive, ok_cb: &Box<dyn Fn(&mut Cursive, &String)>) {
    let pw1_text = match s.call_on_name("pwedit1", |view: &mut EditView| {view.get_content()}) {
        Some(s) => s,
        None => { show_message(s, "Unable to read password"); return }
    };

    let pw2_text = match s.call_on_name("pwedit2", |view: &mut EditView| {view.get_content()}) {
        Some(s) => s,
        None => { show_message(s, "Unable to read password"); return }
    };
    
    if pw1_text != pw2_text {
        show_message(s, "Passwords not equal!");
        return;
    }

    ok_cb(s, &pw2_text);
}

fn file_init_dialog(sndr: Rc<Sender<String>>, ok_cb: Box<dyn Fn(&mut Cursive, &String)>) -> Dialog {
    let sender = sndr.clone();
    
    let verify = move |s: &mut Cursive| {
        verify_passwords(s, &ok_cb);
    };

    let res = Dialog::new()
        .title("Rustpwman create new file")
        .padding_lrtb(2, 2, 1, 1)
        .content(
            LinearLayout::vertical()
            .child(TextView::new("File not found! Enter a new password\n to create a new empty data file.\n\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("New Password   : "))
                    .child(EditView::new()
                        .secret()
                        .with_name("pwedit1")
                        .fixed_width(PW_WIDTH))
            )
            .child(TextView::new("\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("Verify Password: "))
                    .child(EditView::new()
                        .secret()
                        .with_name("pwedit2")
                        .fixed_width(PW_WIDTH))
            )
        )
        .button("OK", verify)
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from("")));

    return res;
}
