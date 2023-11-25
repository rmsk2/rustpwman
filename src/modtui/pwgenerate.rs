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


use std::rc::Rc;
use std::collections::HashSet;
use std::cell::RefCell;
use std::collections::HashMap;
use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, TextArea, SliderView, RadioGroup, RadioButton, Checkbox, HideableView, EditView, Panel, PaddedView};
use cursive::event::EventResult;
use cursive::traits::*;
use cursive::view::Margins;
use itertools::Itertools;

use crate::pwgen::GenerationStrategy;

use super::AppState;
use super::show_message;
use super::edit::insert_into_entry;
use super::PW_MAX_SEC_LEVEL;

const SLIDER_SEC_NAME: &str = "securityslider";
const BITS_SEC_VALUE: &str = "securitybits";
const CUSTOM_HIDEABLE: &str = "hideable_custom";
const CUSTOM_CHARS: &str = "custom_characters";
const CHAR_COUNT: &str = "char_count";


fn show_sec_bits(s: &mut Cursive, val: usize) {
    s.call_on_name(BITS_SEC_VALUE, |view: &mut TextArea| {
        let out = format!("{}", (val + 1) * 8);
        view.set_content(out.clone());
    });
}

fn show_char_count(s: &mut Cursive, data: &str, _c: usize) {
    let temp = String::from(data);    
    let l = eliminate_repititions(&temp).chars().count();
    s.call_on_name(CHAR_COUNT, |view: &mut TextView| { view.set_content(l.to_string()); });   
}

fn on_strategy_changed(s: &mut Cursive, strategy: &GenerationStrategy) {
    let mut custom_visible = false;
    
    if *strategy == GenerationStrategy::Custom {
        custom_visible = true;
    }

    s.call_on_name(CUSTOM_HIDEABLE, |view: &mut HideableView<LinearLayout>| {
        view.set_visible(custom_visible);
    });
}

fn select_default_pw_generator_type(s: &mut Cursive, selector: &mut HashMap<GenerationStrategy, &mut RadioButton<GenerationStrategy>>, def_generator: GenerationStrategy) -> bool {
    let event_result = match selector.get_mut(&def_generator) {
        Some(button) => button.select(),
        None => {
            show_message(s, "Default password generator not found"); 
            return false; 
        }
    };

    match event_result {
        EventResult::Ignored => {
            show_message(s, "Unable to select default password generator"); 
            return false; 
        },
        EventResult::Consumed(c) => {
            match c {
                Some(cb) => { cb(s); true },
                None => true
            }
        }
    }
}

fn set_from_str(s: &String) -> HashSet<char> {
    let mut res = HashSet::<char>::new();

    for i in s.chars() {
        res.insert(i);
    }

    return res;
}

fn str_from_set(s: &HashSet<char>) -> String {
    let mut res = String::from("");

    for i in s {
        res.push(*i);
    }

    return res;
}

fn eliminate_repititions(s: &String) -> String {
    let h = set_from_str(s);
    return str_from_set(&h);
}

#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone)]
enum SelectionType {
    Upper,
    Lower,
    Digits,
    Special,
}

fn on_change_charset(s: &mut Cursive, new_value: bool, st: SelectionType) {
    let current_chars = match s.call_on_name(CUSTOM_CHARS, |view: &mut EditView| { view.get_content() }) {
        Some(v) => v,
        None => { show_message(s, "Unable to determine current character selection"); return }
    };

    let operand: HashSet<char>;

    operand = match st {
        SelectionType::Upper => set_from_str(&String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
        SelectionType::Lower => set_from_str(&String::from("abcdefghijklmnopqrstuvwxyz")),
        SelectionType::Digits => set_from_str(&String::from("0123456789")),
        SelectionType::Special => set_from_str(&String::from("$!#%&")),
    };

    let help = set_from_str(&current_chars);
    let help2: HashSet<char>;

    if new_value {
        help2 = help.union(&operand).map(|c: &char| {*c} ).collect();
    } else {
        help2 = help.difference(&operand).map(|c: &char| {*c} ).collect();
    }

    let new_chars = str_from_set(&help2).chars().sorted().collect::<String>();
    let for_measurement = new_chars.clone();

    s.call_on_name(CUSTOM_CHARS, |view: &mut EditView| { view.set_content(new_chars); });
    show_char_count(s, for_measurement.as_str(), 0)
}


fn on_ok_clicked(s: &mut Cursive, state_for_gen_pw: Rc<RefCell<AppState>>, strategy_group: &RadioGroup<GenerationStrategy>) {
    let rand_bytes = match s.call_on_name(SLIDER_SEC_NAME, |view: &mut SliderView| { view.get_value() }) {
        Some(v) => v,
        None => { show_message(s, "Unable to determine security level"); return }
    };

    let new_pw: String;                    
    let selected_strategy = strategy_group.selection();
    let current_chars: Rc<String>;

    let mut generator = selected_strategy.to_creator()();

    if *selected_strategy == GenerationStrategy::Custom {
        current_chars = match s.call_on_name(CUSTOM_CHARS, |view: &mut EditView| { view.get_content() }) {
            Some(v) => v,
            None => { show_message(s, "Unable to determine current character selection"); return }
        };

        let custom_chars = eliminate_repititions(&current_chars).chars().sorted().collect::<String>();

        if custom_chars.len() < 2 {
            show_message(s, "Not enough unique characters for password generation in selection"); 
            return;
        }

        generator.set_custom(&custom_chars);

        {
            state_for_gen_pw.borrow_mut().last_custom_selection = String::from(custom_chars.as_str());
        }
    }

    new_pw = match generator.gen_password(rand_bytes + 1) {
        Some(pw) => pw,
        None => {
            show_message(s, "Unable to generate password"); 
            return;
        }
    };    

    insert_into_entry(s, new_pw);
    s.pop_layer();        
}

fn create_custom_select(last_selection: &String) -> Box<dyn View> {
    let mut check_boxes = LinearLayout::horizontal();

    let mut check_upper = Checkbox::new().with_checked(false);
    check_upper.set_on_change(|s: &mut Cursive, val: bool| on_change_charset(s, val, SelectionType::Upper));

    check_boxes.add_child(LinearLayout::horizontal()
        .child(check_upper) 
        .child(TextView::new(" Upper case  "))  
    );

    let mut check_lower = Checkbox::new().with_checked(false);
    check_lower.set_on_change(|s: &mut Cursive, val: bool| on_change_charset(s, val, SelectionType::Lower));

    check_boxes.add_child(LinearLayout::horizontal()
        .child(check_lower) 
        .child(TextView::new(" Lower case  "))  
    );

    let mut check_num = Checkbox::new().with_checked(false);
    check_num.set_on_change(|s: &mut Cursive, val: bool| on_change_charset(s, val, SelectionType::Digits));

    check_boxes.add_child(LinearLayout::horizontal()
        .child(check_num) 
        .child(TextView::new(" Digits  "))  
    );

    let mut check_special = Checkbox::new().with_checked(false);
    check_special.set_on_change(|s: &mut Cursive, val: bool| on_change_charset(s, val, SelectionType::Special));

    check_boxes.add_child(LinearLayout::horizontal()
        .child(check_special) 
        .child(TextView::new(" Special  "))  
    );

    return Box::new(Panel::new(
        PaddedView::new(Margins::lrtb(1,1,1,1), 
        LinearLayout::vertical()
        .child(LinearLayout::horizontal()
            .child(TextView::new("Custom characters: "))
            .child(EditView::new()
                .on_edit(show_char_count)
                .content(last_selection.clone())
                .with_name(CUSTOM_CHARS)
                .fixed_width(70)))
        .child(TextView::new("\n"))
        .child(check_boxes)
        .child(TextView::new("\n"))
        .child(LinearLayout::horizontal()
            .child(TextView::new("Number of unique characters: "))
            .child(TextView::new("0")
                .with_name(CHAR_COUNT))
        )
    )).title("Custom character selection"));
}

pub fn generate_password(s: &mut Cursive, state_for_gen_pw: Rc<RefCell<AppState>>) {
    let sec_bits = state_for_gen_pw.borrow().get_default_bits();
    let default_strategy = state_for_gen_pw.borrow().default_generator;

    let mut strategy_group: RadioGroup<GenerationStrategy> = RadioGroup::new();
    let mut radio_buttons: Vec<(GenerationStrategy, RadioButton<GenerationStrategy>)> = Vec::new();

    {
        let mut known_ids = GenerationStrategy::get_known_ids();
        known_ids.push(GenerationStrategy::Custom);

        for i in &known_ids {
            let b = strategy_group.button(*i, i.to_str());
            radio_buttons.push((*i, b));
        }

        let mut selector: HashMap<GenerationStrategy, &mut RadioButton<GenerationStrategy>> = HashMap::new();

        for i in &mut radio_buttons {
            selector.insert(i.0, &mut i.1);
        }
    
        if !select_default_pw_generator_type(s, &mut selector, default_strategy) {
            return;
        }
    }

    let mut linear_layout = LinearLayout::horizontal()
        .child(TextView::new("Contained characters: "));

    for i in radio_buttons {
        linear_layout.add_child(i.1);
        linear_layout.add_child(TextView::new(" "));
    }

    strategy_group.set_on_change(on_strategy_changed);
    let custom_select = create_custom_select(&state_for_gen_pw.borrow().last_custom_selection);
    let h = state_for_gen_pw.borrow().last_custom_selection.clone();
    let for_measurement = h.as_str();

    let res = Dialog::new()
    .title("Rustpwman generate password")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please select parameters for password generation.\n\n"))
        .child(LinearLayout::horizontal()
            .child(TextView::new("Security level "))
            .child(TextArea::new()
                .content("")
                .disabled()
                .with_name(BITS_SEC_VALUE)
                .fixed_height(1)
                .fixed_width(4)
            )            
            .child(TextView::new("Bits: "))
            .child(SliderView::horizontal(PW_MAX_SEC_LEVEL)
                .value(sec_bits)
                .on_change(show_sec_bits)
                .with_name(SLIDER_SEC_NAME))
        )
        .child(TextView::new("\n"))
        .child(linear_layout)
        .child(HideableView::new(
            LinearLayout::vertical()
                .child(TextView::new("\n"))
                .child(custom_select)
            )
            .visible(true)
            .with_name(CUSTOM_HIDEABLE)
        )
    )
    .button("OK", move |s| on_ok_clicked(s, state_for_gen_pw.clone(), &strategy_group))
    .button("Cancel", |s| { s.pop_layer(); });
    
    s.add_layer(res);
    show_sec_bits(s, sec_bits);
    on_strategy_changed(s, &default_strategy);
    show_char_count(s, for_measurement, 0);
}
