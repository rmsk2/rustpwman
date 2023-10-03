use std::rc::Rc;
use std::sync::mpsc::Sender;

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, EditView, DialogFocus};
use cursive::traits::*;

use super::show_message;
use super::pwman_quit;
use super::path_exists;
use super::AppState;
use super::PW_WIDTH;
use crate::fcrypt;

const NAME_PWEDIT : &str = "pwedit";
const NAME_PWDIALOG: &str = "pwdialog";

pub fn dialog(sndr: Rc<Sender<String>>, ok_cb_with_state: Box<dyn Fn(&mut Cursive, &String)>) -> impl View {
    let sender = sndr.clone();

    let ok_cb = move |s: &mut Cursive| {
        let pw_text = match s.call_on_name(NAME_PWEDIT, |view: &mut EditView| {view.get_content()}) {
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
                        .with_name(NAME_PWEDIT)
                        .fixed_width(PW_WIDTH))
                    .with_name("pwlinear")
            )
        )
        .button("OK", ok_cb)
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from(""), false))
        .with_name(NAME_PWDIALOG);

    return res;
}

fn show_pw_error(siv: &mut Cursive, msg: &str) {
    siv.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Ok", |s| {
                s.pop_layer();

                s.call_on_name(NAME_PWEDIT, |view: &mut EditView| {view.set_content(String::from(""))}).unwrap()(s);
                s.call_on_name(NAME_PWDIALOG, |view: &mut Dialog| {view.set_focus(DialogFocus::Content)});
            }),
    );
}

pub fn open_file(s: &mut Cursive, password: &String, state: AppState) -> Option<AppState> {
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
