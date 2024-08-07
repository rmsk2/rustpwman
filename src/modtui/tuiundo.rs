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
use cursive::views::{Dialog, TextView, Panel, ListView};
use cursive::traits::*;


use super::visualize_if_modified;
use super::show_message;
use super::redraw_tui;
use super::AppState;

const NUM_SCROLL_ELEMENTS: usize = 10;
const LIST_VIEW: &str = "undolist";
const SCROLL_VIEW: &str = "undoscroll";

fn handle_undo(s: &mut Cursive, state_for_undo: Arc<Mutex<AppState>>) {
    if !state_for_undo.lock().unwrap().store.is_dirty() {
        show_message(s, "Nothing to undo");
        return;
    }

    let res = state_for_undo.lock().unwrap().store.undo();

    visualize_if_modified(s, state_for_undo.clone());
    redraw_tui(s, state_for_undo.clone());

    if !res.1 {
        show_message(s, "Failed to undo last change");
    }

    s.call_on_name(LIST_VIEW, |view: &mut ListView| { view.remove_child(view.len()-1) });
}

fn handle_undo_all(s: &mut Cursive, state_for_undo_all: Arc<Mutex<AppState>>) {
    if !state_for_undo_all.lock().unwrap().store.is_dirty() {
        show_message(s, "Nothing to undo");
        return;
    }    
    
    while state_for_undo_all.lock().unwrap().store.is_dirty() {
        handle_undo(s, state_for_undo_all.clone());
    }   
}

pub fn undo(s: &mut Cursive, state_for_undo: Arc<Mutex<AppState>>) {
    if !state_for_undo.lock().unwrap().store.is_dirty() {
        show_message(s, "Nothing to undo");
        return;
    }

    let state_for_undo_all = state_for_undo.clone();

    let comments = state_for_undo.lock().unwrap().store.undoer.get_comments();

    let mut list_view = ListView::new();
    
    for i in comments.into_iter() {
        list_view.add_child("", TextView::new(i.as_str()))
    }

    let named_list_view = list_view
    .with_name(LIST_VIEW);
    
    let named_scroll_view = named_list_view
    .scrollable()
    .with_name(SCROLL_VIEW)
    .fixed_height(NUM_SCROLL_ELEMENTS);

    let res = Dialog::new()
    .title("Rustpwman undo actions")
    .padding_lrtb(1, 1, 1, 1)
    .content(
        Panel::new(named_scroll_view)
        .title("Actions to undo")        
    )
    .button("Undo", move |s| {    
        handle_undo(s, state_for_undo.clone())
    })
    .button("Undo all", move |s| {    
        handle_undo_all(s, state_for_undo_all.clone())
    })    
    .button("Cancel", move |s| { 
        s.pop_layer(); 
    });                
    
    s.add_layer(res);      
}

