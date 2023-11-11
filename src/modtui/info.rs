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
use std::cell::RefCell;

use cursive::Cursive;
use cursive::views::{Dialog, TextView};

use super::AppState;


pub fn show(s: &mut Cursive, state_for_info: Rc<RefCell<AppState>>) {
    let num_entries = state_for_info.borrow().store.len();
    let mut msg_str = String::from("");
    let info2: String;
    
    info2 = match state_for_info.borrow().persister.get_canonical_path() {
        Ok(m) => m,
        Err(_) => String::from("Unknown")
    };

    msg_str.push_str(format!("Entry count  : {}\n", num_entries).as_str());
    msg_str.push_str(format!("Location     : {}\n", info2).as_str());
    msg_str.push_str(format!("Access method: {}\n", state_for_info.borrow().persister.get_type()).as_str());

    let res = Dialog::new()
    .title("Rustpwman file info")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        TextView::new(msg_str))
    .button("OK", move |s| {
        s.pop_layer();
    });

    s.add_layer(res);
}