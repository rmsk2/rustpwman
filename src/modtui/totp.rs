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
use cursive::views::{Dialog, LinearLayout, ProgressBar, TextView};
use cursive::Cursive;

use super::AppState;
use super::show_message;
use super::get_selected_entry_name;
use crate::fcrypt::totpcalc;

const TOTP_VIEW: &str = "totp_code_view";
const TOTP_PERIOD: &str = "totp_progr_bar";

fn parse_totp_params(entry_content: String) -> Option<totpcalc::TotpParams> {
    let res = totpcalc::TotpParams::new();

    if !entry_content.starts_with("otpauth://") {
        return None;
    }    

    return Some(res);
}

fn make_progress(value: usize, (_min, _max): (usize, usize)) -> String {
    return format!("{:02} seconds remaining", value);
}

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

    let opt_params = parse_totp_params(entry_content.clone());
    if opt_params.is_none() {
        show_message(s, "Selected entry does not contain a parseable otpauth:// URL");
        return;
    }

    let state_for_stop = state.clone();
    let state_for_start = state.clone();
    let params = opt_params.unwrap();

    s.add_layer(
        Dialog::new()
            .title("TOTP")
            .padding_lrtb(2, 2, 1, 1)
            .content(
                LinearLayout::vertical()
                .child(
                    TextView::new("...")
                    .with_name(TOTP_VIEW)
                )
                .child(TextView::new("\n"))
                .child(
                    ProgressBar::new()
                    .min(1)
                    .max(params.period)
                    .with_label(make_progress)
                    .with_name(TOTP_PERIOD)
                    .fixed_width(30)
                )
            )
            .button("Done", move |s| {
                // This drops the current sender. This in turn causes try_recv() in totp_calc() to return Err(TryRecvError::Disconnected)
                // which is then used to stop the current worker thread
                state_for_stop.lock().unwrap().current_totp_producer = None;
                s.pop_layer();
            })
    );

    start_totp_calc(state_for_start, s, params);
}

fn start_totp_calc(st: Arc<Mutex<AppState>>, siv: &mut Cursive, totp_parms: totpcalc::TotpParams) {
    let receiver: Receiver<()>;

    {
        let mut s = st.lock().unwrap();
        let (tx, rx): (Sender<()>, Receiver<()>) = mpsc::channel();
        // This also causes the current sender to be dropped, which again makes try_recv() in totp_calc() to return
        // Err(TryRecvError::Disconnected) which is then used to stop the current worker thread thread.
        s.current_totp_producer = Some(tx);
        receiver = rx;
    }

    let cb_sink = siv.cb_sink().clone();

    // The new worker thread has a new receiver
    thread::spawn(move || {
        totp_calc(&cb_sink, totp_parms, receiver)
    });
}

fn totp_calc(cb_sink: &CbSink, totp_params: totpcalc::TotpParams, rx: Receiver<()>) {
    let p = totp_params.period as u64;

    loop {
        // If this results in TryRecvError::Disconnected the last sender for this receiver has been dropped. This
        // is detected and used to stop this instance of the worker thread
        match rx.try_recv() {
            Ok(_) | Err(TryRecvError::Disconnected) => break,
            // This is the normal case
            Err(TryRecvError::Empty) => {}
        }

        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let remaining = p - (unix_time % p);            
        let code_as_string = totp_params.get_current_code_formatted(unix_time);

        // Async update to TUI
        let _ = cb_sink.send(Box::new(move |siv: &mut cursive::Cursive| {
            siv.call_on_name(TOTP_VIEW, |view: &mut TextView| {
                view.set_content(code_as_string.clone());
            });

            siv.call_on_name(TOTP_PERIOD, |view: &mut ProgressBar| {
                view.set_value(remaining as usize);
            });            
        }));

        thread::sleep(time::Duration::from_secs(1));
    }
}
