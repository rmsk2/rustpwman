use std::rc::Rc;
use std::cell::RefCell;

use cursive::Cursive;

use super::visualize_if_modified;
use super::show_message;
use super::redraw_tui;
use super::AppState;

pub fn undo(s: &mut Cursive, state_for_undo: Rc<RefCell<AppState>>) {
    if ! state_for_undo.borrow().store.is_dirty() {
        show_message(s, "Nothing to undo");
        return;
    }

    let res = state_for_undo.borrow_mut().store.undo();

    visualize_if_modified(s, state_for_undo.clone());
    redraw_tui(s, state_for_undo.clone());

    if res.1 {
        let msg = format!("{} undone", res.0);
        show_message(s, msg.as_str());
    } else {
        show_message(s, "Failed to undo last change");
    }      
}