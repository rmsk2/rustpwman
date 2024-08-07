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


use std::sync::{Arc, Mutex};

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, EditView};
use cursive::traits::*;

use super::AppState;
use super::show_message;
use super::init::show_pw_select_error;
use super::PW_WIDTH;
use super::save;
#[cfg(feature = "pwmanclient")]
use super::cache;

static PW_EDIT1_CH: &str = "pwchedit1";
static PW_EDIT2_CH: &str = "pwchedit2";
static DLG_PW_CH: &str = "pwchangedlg";


pub fn change(s: &mut Cursive, state_for_pw_change: Arc<Mutex<AppState>>) {
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
                        .with_name(PW_EDIT1_CH)
                        .fixed_width(PW_WIDTH))
            )
            .child(TextView::new("\n"))
            .child(
                LinearLayout::horizontal()
                    .child(TextView::new("Verify Password: "))
                    .child(EditView::new()
                        .secret()
                        .with_name(PW_EDIT2_CH)
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
                show_pw_select_error(s, "Passwords not equal!", PW_EDIT1_CH, PW_EDIT2_CH, DLG_PW_CH);
                return;
            }

            if pw1_text.len() == 0 {
                show_pw_select_error(s, "New password is empty", PW_EDIT1_CH, PW_EDIT2_CH, DLG_PW_CH);
                return;
            }

            let new_pw: String = (&pw1_text).to_string();

            state_for_pw_change.lock().unwrap().password = Some(new_pw);
            save::storage(s, state_for_pw_change.clone());
            s.pop_layer();

            #[cfg(feature = "pwmanclient")]
            cache::uncache_password(s, state_for_pw_change.clone());
        })
        .button("Cancel", |s| { s.pop_layer(); })
        .with_name(DLG_PW_CH);

    s.add_layer(res);
}
