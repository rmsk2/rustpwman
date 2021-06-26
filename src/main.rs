use std::env;

mod tests;
mod fcrypt;
mod jots;
mod pwgen;

const PW_WIDTH: usize = 35;
const PW_SEC_LEVEL: usize = 7;
const PW_MAX_SEC_LEVEL: usize = 24;
const EDIT_NAME: &str = "nameedit";
const TEXT_AREA_MAIN: &str = "entrytext";
const TEXT_AREA_NAME: &str = "textareaedit";
const SCROLL_VIEW: &str = "scrollview";
const SELECT_VIEW: &str = "entrylist";
const PANEL_AREA_MAIN: &str = "entrytitle";
const TEXT_AREA_TITLE: &str = "texttitle";
const EDIT_FILE_NAME: &str = "editfile";
const SLIDER_SEC_NAME: &str = "securityslider";
const BITS_SEC_VALUE: &str = "securitybits";

use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, TextView, EditView, SelectView, TextArea, Panel, SliderView, RadioGroup};
use cursive::Cursive;
use cursive::menu::MenuTree;
use cursive::align::HAlign;
use cursive::event::Key;

use std::rc::Rc;
use std::cell::RefCell;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::fs;

use pwgen::GenerationStrategy;
use pwgen::PasswordGenerator;

pub fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

pub struct AppState {
    store: jots::Jots,
    password: Option<String>,
    file_name: String,
    dirty: bool
}

impl AppState {
    fn new(s: jots::Jots, f_name: &String) -> Self {
        return AppState {
            store: s,
            password: None,
            file_name: f_name.clone(),
            dirty: false  
        }
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

    let item = match get_selected_entry_name(s) {
        Some(k) => k,
        _ => { show_message(s, "Unable to read entry"); return; }
    };

    let text_val_opt = s.call_on_name(TEXT_AREA_MAIN, |view: &mut TextArea| -> String { String::from(view.get_content()) });  
    let text_val = match text_val_opt {
        Some(st) => st,
        None => { show_message(s, "Unable to read entry"); return; }
    };

    let mut mut_state = state_temp_save.borrow_mut();

    mut_state.store.insert(&item, &text_val);
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
    match get_selected_entry_name(s) {
        Some(name) => {
            let res = Dialog::new()
            .title("Rustpwman delete entry")
            .padding_lrtb(2, 2, 1, 1)
            .content(
                LinearLayout::vertical()
                .child(TextView::new(format!("Delete entry \"{}\"?", &name)))
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
                let new_text = String::from("New entry");
                state_for_add_entry.borrow_mut().store.insert(&entry_name, &new_text);
                state_for_add_entry.borrow_mut().dirty = true;
                fill_tui(s, state_for_add_entry.clone());
                s.pop_layer();
                display_entry(s, state_for_add_entry.clone(), &entry_name, true);
                show_message(s, "Entry created successfully. It has been selected\n but you may need to scroll to it manually.");
            }
        }
    })
    .button("Cancel", |s| { s.pop_layer(); });                
    
    s.add_layer(res);
}

fn load_entry(s: &mut Cursive, state_for_add_entry: Rc<RefCell<AppState>>) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    }; 

    let res = Dialog::new()
    .title("Rustpwman enter load entry from file")
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
    )
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
    })
    .button("Cancel", |s| { s.pop_layer(); });                
    
    s.add_layer(res);
}

fn show_sec_bits(s: &mut Cursive, val: usize) {
    s.call_on_name(BITS_SEC_VALUE, |view: &mut TextArea| {
        let out = format!("{}", (val + 1) * 8);
        view.set_content(out.clone());
    });
}

fn generate_password(s: &mut Cursive, state_for_gen_pw: Rc<RefCell<AppState>>) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    }; 

    let mut strategy_group: RadioGroup<GenerationStrategy> = RadioGroup::new();

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
                .value(PW_SEC_LEVEL)
                .on_change(|s, slider_val| { show_sec_bits(s, slider_val) })
                .with_name(SLIDER_SEC_NAME))
        )
        .child(TextView::new("\n"))
        .child(LinearLayout::horizontal()
            .child(TextView::new("Contained characters: "))
            .child(strategy_group.button(GenerationStrategy::Base64, "Base64"))
            .child(TextView::new(" "))
            .child(strategy_group.button(GenerationStrategy::Hex, "Hex"))
            .child(TextView::new(" "))
            .child(strategy_group.button(GenerationStrategy::Special, "Special"))            
        )
    )
    .button("OK", move |s| {
        let mut value = match state_for_gen_pw.borrow().store.get(&entry_name) {
            Some(c) => c,
            None => { show_message(s, "Unable to read value of entry"); return }
        };

        let rand_bytes = match s.call_on_name(SLIDER_SEC_NAME, |view: &mut SliderView| { view.get_value() }) {
            Some(v) => v,
            None => { show_message(s, "Unable to determine security level"); return }
        };

        let b64_gen = pwgen::B64Generator::new();
        let hex_gen = pwgen::HexGenerator::new();

        let mut generator: Box<dyn PasswordGenerator> = match *strategy_group.selection() {
            GenerationStrategy::Base64 => Box::new(b64_gen),
            GenerationStrategy::Hex => Box::new(hex_gen),
            _ => Box::new(hex_gen)
        };

        let new_pw = match generator.gen_password(rand_bytes + 1) {
            Some(pw) => pw,
            None => {
                show_message(s, "Unable to generate password"); 
                return;
            }
        };

        value.push_str(&new_pw);

        state_for_gen_pw.borrow_mut().store.insert(&entry_name, &value);
        state_for_gen_pw.borrow_mut().dirty = true;
        s.pop_layer();
        display_entry(s, state_for_gen_pw.clone(), &entry_name, true);        
    })
    .button("Cancel", |s| { s.pop_layer(); });
    
    s.add_layer(res);
    show_sec_bits(s, PW_SEC_LEVEL);
}

fn edit_entry(s: &mut Cursive, state_for_edit_entry: Rc<RefCell<AppState>>) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    }; 

    let content = match state_for_edit_entry.borrow().store.get(&entry_name) {
        Some(c) => c,
        None => { show_message(s, "Unable to read value of entry"); return }
    };

    let res = Dialog::new()
    .title("Rustpwman enter new text")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please enter new text for entry.\n\n"))
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

        state_for_edit_entry.borrow_mut().store.insert(&entry_name, &entry_text);
        state_for_edit_entry.borrow_mut().dirty = true;
        display_entry(s, state_for_edit_entry.clone(), &entry_name, true);

        s.pop_layer();
    })
    .button("Cancel", |s| { s.pop_layer(); });                
    
    s.add_layer(res);
}

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
                        .with_name("pwchedit1")
                        .fixed_width(PW_WIDTH))
            )
            .child(TextView::new("\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("Verify Password: "))
                    .child(EditView::new()
                        .secret()
                        .with_name("pwchedit2")
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
                show_message(s, "Passwords not equal!");
                return;
            }

            let new_pw: String = (&pw1_text).to_string();

            state_for_pw_change.borrow_mut().password = Some(new_pw);
            process_save_command(s, state_for_pw_change.clone());
            s.pop_layer();
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
    let state_temp_pw = shared_state.clone();
    let state_temp_edit = shared_state.clone();
    let state_temp_load = shared_state.clone();
    let state_temp_pw_gen = shared_state.clone();    
    let sender = sndr.clone();
    let sender2 = sndr.clone();

    let state_for_callback = shared_state.clone();
    let state_for_fill_tui = shared_state.clone();

    s.menubar()    
    .add_subtree(
        "File", MenuTree::new()
            .leaf("Save File", move |s| { 
                process_save_command(s, state_temp_save.clone()); 
            })
            .leaf("Change password ...", move |s| {
                change_password(s, state_temp_pw.clone())
            })
            .delimiter()
            .leaf("About ...", |s| {
                show_message(s, "\n   A basic password manager\n\nWritten by Martin Grap in 2021\n")
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
            .leaf("Quit", move |s| pwman_quit(s, sender.clone(), String::from(""), shared_state.borrow().dirty ))
        )
        .add_subtree(
            "Entry", MenuTree::new()
            .leaf("Edit Entry ...", move |s| {
                edit_entry(s, state_temp_edit.clone())
            })        
            .leaf("Add Entry ...", move |s| {
                add_entry(s, state_temp_add.clone());
            })
            .leaf("Delete Entry", move |s| {
                delete_entry(s, state_temp_del.clone()); 
            })            
            .leaf("Load Entry ...", move |s| {
                load_entry(s, state_temp_load.clone())  
            })        
            .leaf("Generate password ...", move |s| {
                generate_password(s, state_temp_pw_gen.clone())
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
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from(""), false));

    return res;
}

fn verify_passwords(s: &mut Cursive, ok_cb: &Box<dyn Fn(&mut Cursive, &String)>) {
    verify_passwords_with_names(s, ok_cb, "pwedit1", "pwedit2");
}

fn verify_passwords_with_names(s: &mut Cursive, ok_cb: &Box<dyn Fn(&mut Cursive, &String)>, edit1: &str, edit2: &str) {
    let pw1_text = match s.call_on_name(edit1, |view: &mut EditView| {view.get_content()}) {
        Some(s) => s,
        None => { show_message(s, "Unable to read password"); return }
    };

    let pw2_text = match s.call_on_name(edit2, |view: &mut EditView| {view.get_content()}) {
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
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from(""), false));

    return res;
}
