use std::env;

mod tests;
mod fcrypt;
mod jots;

use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, TextView, EditView, SelectView, TextArea, Panel};
use cursive::Cursive;
use cursive::menu::MenuTree;
use cursive::align::HAlign;

use std::fs;

pub fn path_exists(path: &str) -> bool {
    fs::metadata(path).is_ok()
}

pub struct AppState {
    store: jots::Jots,
    password: Option<String>,
    file_name: String
}

impl AppState {
    fn new(s: jots::Jots, f_name: &String) -> Self {
        return AppState {
            store: s,
            password: None,
            file_name: f_name.clone()
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.len() < 1 {
        println!("Usage: rustpwman <encrypted data file>");
        return;
    }

    let data_file_name = &args[0].clone();
    let capture_file_name = data_file_name.clone();
    let mut siv = cursive::default();

    let pw_callback = Box::new(move |s: &mut Cursive, password: &String| {
        let jots_store = jots::Jots::new();
        let f_name = capture_file_name.clone();
        let state = AppState::new(jots_store, &f_name);

        if let Some(state_after_open) = open_file(s, password, state) {
            main_window(s, state_after_open);
        }
    });

    if path_exists(&data_file_name) {
        let d = password_entry_dialog(pw_callback);
        siv.add_layer(d);
    } else {
        let d = file_init_dialog(pw_callback);
        siv.add_layer(d);
    }

    siv.run();
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

fn main_window(s: &mut Cursive, state: AppState) {
    let mut select_view = SelectView::new();
    let mut count = 0;
    let mut initial_text = String::from("");

    s.menubar()
    
    .add_subtree(
        "File", MenuTree::new()
            .leaf("Add Entry", |_s| {})
            .leaf("Delete Entry", |_s| {})
            .delimiter()
            .leaf("Save File", |_s| {})
            .leaf("Change password", |_s| {})
            .delimiter()
            .leaf("Quit", |s| s.quit()));

    s.set_autohide_menu(false);

    for i in &state.store {
        if count == 0 {
            initial_text = match state.store.get(i) {
                Some(s) => s,
                None => { panic!("This should not have happened"); }
            }
        }
        select_view.add_item(i.clone(), i.clone());

        count += 1;
    }
    
    let select_view_attributed = select_view
        .h_align(HAlign::Center)
        .on_select(move |s, item| {
            let entry_text = match state.store.get(item) {
                Some(s) => s,
                None => {
                    show_message(s, "Unable to read password"); return;
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
                .content(initial_text)
                .with_name("entrytext")
                .fixed_width(100)
                .min_height(40)
        )
        .title("Contents of entry")
    );
    
    s.add_layer(tui);
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

fn password_entry_dialog(ok_cb_with_state: Box<dyn Fn(&mut Cursive, &String)>) -> Dialog {
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
                        .fixed_width(20))
            )
        )
        .button("OK", ok_cb)
        .button("Cancel", |s| s.quit());

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

fn file_init_dialog(ok_cb: Box<dyn Fn(&mut Cursive, &String)>) -> Dialog {
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
                        .fixed_width(20))
            )
            .child(TextView::new("\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("Verify Password: "))
                    .child(EditView::new()
                        .secret()
                        .with_name("pwedit2")
                        .fixed_width(20))
            )
        )
        .button("OK", verify)
        .button("Cancel", |s| s.quit());

    return res;
}
