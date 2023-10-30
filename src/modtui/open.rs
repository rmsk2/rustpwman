use cursive::Cursive;

use super::AppState;
use super::show_message;
use super::path_exists;
use super::pwentry::show_pw_error;

pub fn file(s: &mut Cursive, password: &String, state: AppState) -> Option<AppState> {
    let file_name = state.file_name.clone();
    let mut state = state;
    
    if !path_exists(&file_name) {
        match state.store.to_enc_file(&file_name, password) {
            Ok(_) => (),
            Err(_) => {
                show_message(s, &format!("Unable to initialize file\n\n{}", &file_name));
                return None;
            }
        }
    }

    match state.store.from_enc_file(&file_name, password) {
        Ok(_) => { },
        Err(e) => {
            show_pw_error(s, &format!("Unable to read file '{}'\n\nError: '{:?}'", file_name, e));
            return None;                
        }
    }

    state.password = Some(password.clone());

    return Some(state);
}