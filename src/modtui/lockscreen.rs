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

use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, TextView, EditView, DummyView};
use cursive::Cursive;
use cursive::menu::Item;
use std::sync::{Arc, Mutex};

use super::AppState;
use super::show_message;
use super::refocus_dlg_element;

fn iterate_all_menu_entries(s: &mut Cursive, new_value: bool){
    let menu_bar = s.menubar();

    for i in 0..menu_bar.len() {
        if let Some(tree) = menu_bar.get_subtree(i) {
            for item in tree.children.iter_mut() {
                if let Item::Leaf {enabled, ..} = item {
                    *enabled = new_value;
                }
            }
        }        
    }
}

const LOCK_LAYER: &str = "lock_layer";
const LOCK_PW_EDIT: &str = "lock_pw_edit";
const LOCK_MESSAGE: &str = "lock_message";
const TEXT_UNLOCK_ACTIVE: &str = "Rustpwman is locked. Enter unlock code or master password.";
const TEXT_UNLOCK_INACTIVE: &str = "Rustpwman is locked. Enter master password.";

pub fn activate(s: &mut Cursive, current_state: Arc<Mutex<AppState>>) {
    let state_for_button_press = current_state.clone();
    let state_for_submit = current_state.clone();
    let user_msg: &str;

    if current_state.lock().unwrap().locked {
        return;
    }

    if current_state.lock().unwrap().is_unlock_code_active() {
        user_msg = TEXT_UNLOCK_ACTIVE;
    } else {
        user_msg = TEXT_UNLOCK_INACTIVE;
    }

    let lock_view = Dialog::around(
            LinearLayout::vertical()
                .child(TextView::new(user_msg)
                    .with_name(LOCK_MESSAGE)
                )
                .child(TextView::new("\n"))
                .child(EditView::new()
                    .secret()
                    .on_submit(move |s, pw| { deactivate(s, state_for_submit.clone(), Some(String::from(pw))); })
                    .with_name(LOCK_PW_EDIT))
        )
        .title("Locked")
        .button("Unlock", move |s| {deactivate(s, state_for_button_press.clone(), None);})
        .with_name(LOCK_LAYER);

    let centered = LinearLayout::vertical()
        .child(DummyView.full_height())
        .child(LinearLayout::horizontal()
            .child(DummyView.full_width())
            .child(lock_view)
            .child(DummyView.full_width()))
        .child(DummyView.full_height());

    s.add_fullscreen_layer(centered.full_screen());

    iterate_all_menu_entries(s, false);

    current_state.lock().unwrap().locked = true;
}

fn deactivate(s: &mut Cursive, current_state: Arc<Mutex<AppState>>, pw: Option<String>) {
    if !current_state.lock().unwrap().locked {
        return;
    }

    let user_pass: String;

    if let Some(password) = pw {
        user_pass = password;
    } else {
        let pw_text = match s.call_on_name(LOCK_PW_EDIT, |view: &mut EditView| {view.get_content()}) {
            Some(s) => s,
            None => { show_message(s, "Unable to read password"); return }
        };

        user_pass = String::from(pw_text.as_str());
    }    

    if !current_state.lock().unwrap().verify_unlock_password(user_pass) {        
        s.call_on_name(LOCK_PW_EDIT, |view: &mut EditView| {view.set_content(String::from(""))}).unwrap()(s);
        refocus_dlg_element(s, LOCK_LAYER, LOCK_PW_EDIT);

        if !current_state.lock().unwrap().is_unlock_code_active() {
            s.call_on_name(LOCK_MESSAGE, |view: &mut TextView| {view.set_content(TEXT_UNLOCK_INACTIVE)});
        }

        show_message(s, "Password not acceptable");
        return;
    }

    let screen = s.screen_mut();
    if let Some(pos) = screen.find_layer_from_name(LOCK_LAYER) {
        screen.remove_layer(pos);
        iterate_all_menu_entries(s, true);
        current_state.lock().unwrap().locked = false;
    } else {
        show_message(s, "Unable to find layer of lock screen. This should not have happened");
        return;
    }
}
