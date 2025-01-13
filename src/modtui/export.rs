/* Copyright 2025 Martin Grap

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
use std::sync::mpsc::Sender;

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, SelectView, TextArea, Panel, NamedView, ScrollView, ResizedView};

use super::AppState;
use super::pwman_quit;


pub fn window(s: &mut Cursive, state: AppState, sndr: Arc<Sender<String>>) {
    let msg = "ToDo: Implement export feature";
    let sndr_ok = sndr.clone();
    let sndr_cancel = sndr.clone();
    let shared_state: Arc<Mutex<AppState>> = Arc::new(Mutex::new(state));
    let state_ok = shared_state.clone();

    s.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Cancel", move |s| {
                s.pop_layer();
                pwman_quit(s, sndr_ok.clone(), String::from(""))
            })
            .button("Ok", move |s| {
                let test: String;
                
                // Artificial scope to enforce unlock()
                {
                    let st = state_ok.lock().unwrap();
                    test = st.copy_command.clone();
                }

                s.pop_layer();
                pwman_quit(s, sndr_cancel.clone(), test)
            }),
    );   
}