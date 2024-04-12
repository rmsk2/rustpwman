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


use std::rc::Rc;
use std::sync::mpsc::Sender;

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, EditView, DialogFocus};
use cursive::traits::*;
use cursive::event::EventResult;
use cursive::view::Selector::Name;

use super::show_message;
use super::pwman_quit;
use super::PW_WIDTH;
use crate::fcrypt;

static PW_EDIT1: &str = "pwedit1";
static PW_EDIT2: &str = "pwedit2";
static DLG_INIT: &str = "pwinit";

fn verify_passwords(s: &mut Cursive, ok_cb: &Box<dyn Fn(&mut Cursive, &String, bool)>) {
    verify_passwords_with_names(s, ok_cb, PW_EDIT1, PW_EDIT2, DLG_INIT);
}

pub fn show_pw_select_error(siv: &mut Cursive, msg: &str, edit1: &'static str, edit2: &'static str, dlg: &'static str) {
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

fn verify_passwords_with_names(s: &mut Cursive, ok_cb: &Box<dyn Fn(&mut Cursive, &String, bool)>, edit1: &'static str, edit2: &'static str, dlg: &'static str) {
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

    if let Some(err) = fcrypt::check_password(&pw1_text) {
        show_pw_select_error(s, &format!("Password incorrect: {:?}", err), edit1, edit2, dlg);
        return;        
    }

    ok_cb(s, &pw2_text, false);
}

pub fn dialog(sndr: Rc<Sender<String>>, ok_cb: Box<dyn Fn(&mut Cursive, &String, bool)>) -> impl View {
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
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from("")))
        .with_name(DLG_INIT);

    return res;
}
