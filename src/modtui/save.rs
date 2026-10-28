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

use super::AppState;
use super::show_message;
use super::visualize_if_modified;

pub fn storage_cb(s: &mut Cursive, state_temp_save: Arc<Mutex<AppState>>) {
    let bkp_result = Arc::new(Mutex::new(crate::jots::BackupResult::Ok));
    storage(s, state_temp_save, bkp_result, true);
}

pub fn storage(s: &mut Cursive, state_temp_save: Arc<Mutex<AppState>>, bkp_result: Arc<Mutex<crate::jots::BackupResult>>, show_bkp_warning: bool) {
    let calc_err_msg = |e: std::io::Error| -> String {
        return format!("Unable to save: {}", e);
    };

    storage_with_message(s, state_temp_save, bkp_result, show_bkp_warning, calc_err_msg);
}

pub fn after_pw_change(s: &mut Cursive, state_temp_save: Arc<Mutex<AppState>>, bkp_result: Arc<Mutex<crate::jots::BackupResult>>, show_bkp_warning: bool) {
    let calc_err_msg = |e: std::io::Error| -> String {
        return format!("Unable to save: {}. This also means the file on disk does still use the old password! You can attempt to use the 'Save File' menu entry to retry", e);
    };

    storage_with_message(s, state_temp_save, bkp_result, show_bkp_warning, calc_err_msg);
}

fn storage_with_message(s: &mut Cursive, state_temp_save: Arc<Mutex<AppState>>, bkp_result: Arc<Mutex<crate::jots::BackupResult>>, show_bkp_warning: bool, create_err_msg: impl Fn(std::io::Error) -> String) {
    let bkp_res: crate::jots::BackupResult;
    *bkp_result.lock().unwrap() = crate::jots::BackupResult::Ok;

    // force release of mutable reference to state_temp_save before
    // calling visualize_if_modified
    {
        let mut mut_state = state_temp_save.lock().unwrap();

        match mut_state.persist_store() {
            Ok(val) => {
                bkp_res = val
            }
            Err(e) => {
                show_message(s, create_err_msg(e).as_str());
                return;
            }
        }
    }

    *bkp_result.lock().unwrap() = bkp_res;
    visualize_if_modified(s, state_temp_save.clone());

    if show_bkp_warning && bkp_res != crate::jots::BackupResult::Ok {        
        show_message(s, "Warning: While saving the file was successful, creating a local backup of it failed");
    }
}