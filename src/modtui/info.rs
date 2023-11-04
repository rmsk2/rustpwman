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