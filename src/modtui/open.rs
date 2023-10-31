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