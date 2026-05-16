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
use std::{thread, time};
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::time::SystemTime;

use cursive::CbSink;
use cursive::traits::*;
use cursive::views::{Dialog, TextView};
use cursive::Cursive;

use super::AppState;
use super::show_message;
use super::get_selected_entry_name;

const TOTP_VIEW: &str = "totp_code_view";

pub fn show(s: &mut Cursive, state: Arc<Mutex<AppState>>) {
    let entry_name = match get_selected_entry_name(s) {
        Some(name) => name,
        None => {
            show_message(s, "Unable to determine selected entry");
            return;
        }
    };

    let entry_content = match state.lock().unwrap().store.get(&entry_name) {
        Some(c) => c,
        None => {
            show_message(s, "Unable to read value of entry");
            return;
        }
    };

    if !entry_content.starts_with("otpauth://") {
        show_message(s, "Selected entry does not contain an otpauth:// URL");
        return;
    }

    let state_for_stop = state.clone();
    let state_for_start = state.clone();

    s.add_layer(
        Dialog::new()
            .title("TOTP")
            .padding_lrtb(2, 2, 1, 1)
            .content(
                TextView::new("...")
                    .with_name(TOTP_VIEW)
            )
            .button("Done", move |s| {
                state_for_stop.lock().unwrap().current_totp_producer = None;
                s.pop_layer();
            })
    );

    start_totp_calc(state_for_start, s, entry_content);
}

fn start_totp_calc(st: Arc<Mutex<AppState>>, siv: &mut Cursive, totp_url: String) {
    let receiver: Receiver<bool>;

    {
        let mut s = st.lock().unwrap();
        let (tx, rx): (Sender<bool>, Receiver<bool>) = mpsc::channel();
        s.current_totp_producer = Some(tx);
        receiver = rx;
    }

    let cb_sink = siv.cb_sink().clone();

    thread::spawn(move || {
        totp_calc(&cb_sink, totp_url, receiver)
    });
}

fn totp_calc(cb_sink: &CbSink, _totp_url: String, rx: Receiver<bool>) {
    loop {
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }

        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Stub: replace with actual TOTP code generation using _totp_url
        let code = format!("{:06}", unix_time % 1_000_000);
        let remaining = 30 - (unix_time % 30);
        let display = format!("Code: {}  ({} s remaining)", code, remaining);

        let _ = cb_sink.send(Box::new(move |siv: &mut cursive::Cursive| {
            siv.call_on_name(TOTP_VIEW, |view: &mut TextView| {
                view.set_content(display.clone());
            });
        }));

        thread::sleep(time::Duration::from_secs(1));
    }
}
