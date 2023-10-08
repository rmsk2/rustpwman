use std::rc::Rc;
use std::cell::RefCell;

use cursive::Cursive;

use super::AppState;
use super::show_message;
use super::visualize_if_modified;

pub fn file(s: &mut Cursive, state_temp_save: Rc<RefCell<AppState>>) {
    let password = match state_temp_save.borrow().password.clone() {
        Some(p) => p,
        None => { show_message(s, "Unable to read password"); return; }
    };

    {
        let mut mut_state = state_temp_save.borrow_mut();
        let file_name = mut_state.file_name.clone();
    
        if let Err(e) = mut_state.store.to_enc_file(&file_name, &password) {
            show_message(s, &format!("Unable to save: {:?}", e)); 
            return; 
        }    
    }

    visualize_if_modified(s, state_temp_save.clone());
}