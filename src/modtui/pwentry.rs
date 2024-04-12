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

use super::show_message;
use super::pwman_quit;
use super::PW_WIDTH;
use crate::fcrypt;

const NAME_PWEDIT : &str = "pwedit";
const NAME_PWDIALOG: &str = "pwdialog";

pub fn dialog(sndr: Rc<Sender<String>>, ok_cb_with_state: Box<dyn Fn(&mut Cursive, &String, bool)>) -> impl View {
    let sender = sndr.clone();

    let ok_cb = move |s: &mut Cursive| {
        let pw_text = match s.call_on_name(NAME_PWEDIT, |view: &mut EditView| {view.get_content()}) {
            Some(s) => s,
            None => { show_message(s, "Unable to read password"); return }
        };

        if let Some(err) = fcrypt::check_password(&pw_text) {
            show_message(s, &format!("Password incorrect: {:?}", err));
            return;        
        }        

        ok_cb_with_state(s, &pw_text, false);
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
        .button("Cancel", move |s| pwman_quit(s, sender.clone(), String::from("")))
        .with_name(NAME_PWDIALOG);

    return res;
}

pub fn show_pw_error(siv: &mut Cursive, msg: &str) {
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
