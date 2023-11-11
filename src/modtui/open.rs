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


use cursive::Cursive;

use super::AppState;
use super::show_message;
use super::pwentry::show_pw_error;

pub fn storage(s: &mut Cursive, password: &String, state: AppState) -> Option<AppState> {
    let mut state = state;

    let does_exist = match state.persister.does_exist() {
        Ok(b) => b,
        Err(e) => {
            show_message(s, &format!("Unable to check for existence of: {:?}", e));
            return None;
        }
    };
    
    if !does_exist {
        match state.store.persist(&mut state.persister, password) {
            Ok(_) => (),
            Err(e) => {
                show_message(s, &format!("Unable to initialize password storage: {:?}", e));
                return None;
            }
        }
    }

    match state.store.retrieve(&mut state.persister, password) {
        Ok(_) => { },
        Err(e) => {
            show_pw_error(s, &format!("Unable to read password storage: '{:?}'", e));
            return None;                
        }
    }

    state.password = Some(password.clone());

    return Some(state);
}