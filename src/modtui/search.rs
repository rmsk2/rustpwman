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
use cursive::views::{Dialog, LinearLayout, Panel, TextView, SelectView, EditView, OnEventView};
use cursive::traits::*;
use std::sync::{Arc, Mutex};
use cursive::event::Key;

use super::AppState;
use super::show_message;
use super::display_entry;

const SELECT_VIEW: &str = "select_entry_view";
const EDIT_SEARCH_TERM: &str = "search_term_edit";
const NUM_SCROLL_ELEMENTS: usize = 20;


pub fn perform_search(s: &mut Cursive, state_for_add_entry: Arc<Mutex<AppState>>) {
    let mut search_res: Vec<String> = vec![];

    let search_term = match s.call_on_name(EDIT_SEARCH_TERM, |view: &mut EditView| { view.get_content() }) {
        Some(s) => {
            s.clone()
        },
        None => { show_message(s, "Unable to read search term"); return }
    };

    if search_term.is_empty() {
        show_message(s, "No search term defined"); 
        return 
    }

    s.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.clear(); } );

    // create artificial scope to ensure unlocking of global state
    {
        let state = state_for_add_entry.lock().unwrap();
        search_res = state.store.search(&search_term);
    }

    if search_res.is_empty() {
        show_message(s, "No matching entry found"); 
        return 
    }

    for i in search_res {
        s.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.add_item(i.clone(), i.clone()); } );
    }
}

pub fn do_select(s: &mut Cursive, state_for_select: Arc<Mutex<AppState>>) {
    let id_opt = match s.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.selected_id() }) {
        Some(i) => i,
        None => {show_message(s, "No element selected"); return; }
    };

    if let Some(id) = id_opt {
        let help = s.call_on_name(SELECT_VIEW, |view: &mut SelectView| -> Option<String> {
            match view.get_item(id) {
                Some(t) => Some(String::from(t.0)),
                _ => None
            }
        });

        let entry_name = match help {
            Some(Some(egal)) => egal,
            _ => {show_message(s, "No element selected"); return; }
        };

        s.pop_layer();
        display_entry(s, state_for_select.clone(), &entry_name, true);
        show_message(s, "The entry has been successfully selected\nbut you may need to scroll to it manually.");
    } else {
        show_message(s, "No element selected");
    }
}

pub fn entry(s: &mut Cursive, state_for_search_entry: Arc<Mutex<AppState>>) {
    let state_for_perf_search = state_for_search_entry.clone();
    let state_for_select = state_for_search_entry.clone();
    let state_for_enter_callback = state_for_perf_search.clone();

    let select_view = SelectView::<String>::new();
    let named_select_view = select_view
    .autojump()
    .with_name(SELECT_VIEW);

    let mut event_wrapped_select_view = OnEventView::new(named_select_view);
    event_wrapped_select_view.set_on_event(Key::Enter, move |s| { do_select(s, state_for_enter_callback.clone()); });

    let scroll_view = event_wrapped_select_view
    .scrollable()
    .fixed_height(NUM_SCROLL_ELEMENTS);

    let res = Dialog::new()
    .title("Rustpwman search entry")
    .padding_lrtb(1, 1, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(
            Panel::new(scroll_view)
            .title("Found entries")
        )
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("Search for: "))
                .child(EditView::new()
                    .with_name(EDIT_SEARCH_TERM)
                    .fixed_width(60))            
        )
    )
    .button("Search", move |s| { perform_search(s, state_for_perf_search.clone()); })
    .button("Select", move |s| { do_select(s, state_for_select.clone()); })
    .button("Clear all", move |s| {
        s.call_on_name(SELECT_VIEW, |view: &mut SelectView| { view.clear(); } );
        s.call_on_name(EDIT_SEARCH_TERM, |view: &mut EditView| { view.set_content(String::from("")) }).unwrap()(s);
     })
    .button("Cancel", move |s| { s.pop_layer(); });

    s.add_layer(res);      
}