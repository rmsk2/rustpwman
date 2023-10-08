use std::rc::Rc;
use std::cell::RefCell;

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView};

use super::AppState;
use super::show_message;
use super::get_selected_entry_name;
use super::display_entry;
use super::get_special_styles;
use super::visualize_if_modified;


pub fn entry(s: &mut Cursive, state_temp_clear: Rc<RefCell<AppState>>) { 
    let (danger_style, reverse_style) = get_special_styles(); 

    match get_selected_entry_name(s) {
        Some(name) => {
            let res = Dialog::new()
            .title("Rustpwman clear entry")
            .padding_lrtb(2, 2, 1, 1)
            .content(
                LinearLayout::vertical()
                .child(
                    LinearLayout::horizontal()
                    .child(TextView::new("The Entry "))
                    .child(TextView::new(name.as_str())
                        .style(reverse_style))
                        .child(TextView::new(" will be "))
                        .child(TextView::new("CLEARED")
                            .style(danger_style))    
                        .child(TextView::new(". Do you want to proceed?"))
                )
            )
            .button("Cancel", |s| { s.pop_layer(); })            
            .button("OK", move |s| {
                let empty = String::from("Empty entry\n");
                state_temp_clear.borrow_mut().store.insert(&name, &empty);
                s.pop_layer();
                visualize_if_modified(s, state_temp_clear.clone());
                display_entry(s, state_temp_clear.clone(), &name, true);
            });
            
            s.add_layer(res); 
        },
        None => {
            show_message(s, "Unable to determine selected entry"); 
            return; 
        }
    } 
}
