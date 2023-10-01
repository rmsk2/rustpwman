use std::rc::Rc;
use std::cell::RefCell;

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, EditView};
use cursive::traits::*;

use super::AppState;
use super::show_message;
use super::display_entry;
use super::edit::entry as edit_entry;
use super::fill_tui;

const EDIT_NAME: &str = "nameedit";

pub fn entry(s: &mut Cursive, state_for_add_entry: Rc<RefCell<AppState>>) {
    let res = Dialog::new()
    .title("Rustpwman enter new entry name")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please enter a new name for an entry.\n\n"))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("New name: "))
                .child(EditView::new()
                    .with_name(EDIT_NAME)
                    .fixed_width(40))
        )
    )
    .button("OK", move |s| {
        let entry_name = match s.call_on_name(EDIT_NAME, |view: &mut EditView| {view.get_content()}) {
            Some(entry) => {
                if entry.len() == 0 {
                    show_message(s, "Entry is empty"); 
                    return;
                }
                entry.clone()
            },
            None => { show_message(s, "Unable to read new entry"); return }
        }; 

        let old_entry: Option<String>;

        {
            old_entry = state_for_add_entry.borrow().store.get(&entry_name);
        }

        match old_entry {
            Some(_) => { show_message(s, "Entry already exists"); return },
            None => {
                let new_text = String::from("New entry\n");
                state_for_add_entry.borrow_mut().store.insert(&entry_name, &new_text);
                state_for_add_entry.borrow_mut().dirty = true;
                fill_tui(s, state_for_add_entry.clone());
                s.pop_layer();

                display_entry(s, state_for_add_entry.clone(), &String::from(entry_name.as_str()), true);
                edit_entry(s, state_for_add_entry.clone(), Some(entry_name));
            }
        }
    })
    .button("Cancel", |s| { s.pop_layer(); });                
    
    s.add_layer(res);
}
