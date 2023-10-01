use std::rc::Rc;
use std::cell::RefCell;
use std::collections::HashMap;
use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, TextArea, SliderView, RadioGroup, RadioButton};
use cursive::event::EventResult;
use cursive::traits::*;

use crate::pwgen::GenerationStrategy;
use crate::pwgen::PasswordGenerator;

use super::AppState;
use super::show_message;
use super::edit::insert_into_entry;
use super::PW_MAX_SEC_LEVEL;

const SLIDER_SEC_NAME: &str = "securityslider";
const BITS_SEC_VALUE: &str = "securitybits";


fn show_sec_bits(s: &mut Cursive, val: usize) {
    s.call_on_name(BITS_SEC_VALUE, |view: &mut TextArea| {
        let out = format!("{}", (val + 1) * 8);
        view.set_content(out.clone());
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

pub fn generate_password(s: &mut Cursive, state_for_gen_pw: Rc<RefCell<AppState>>) {
    let sec_bits = state_for_gen_pw.borrow().get_default_bits();
    let default_strategy = state_for_gen_pw.borrow().default_generator;

    let mut strategy_group: RadioGroup<GenerationStrategy> = RadioGroup::new();
    let mut radio_buttons: Vec<(GenerationStrategy, RadioButton<GenerationStrategy>)> = Vec::new();

    {
        for i in &GenerationStrategy::get_known_ids() {
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
                .on_change(|s, slider_val| { show_sec_bits(s, slider_val) })
                .with_name(SLIDER_SEC_NAME))
        )
        .child(TextView::new("\n"))
        .child(linear_layout)
    )
    .button("OK", move |s| {
        let rand_bytes = match s.call_on_name(SLIDER_SEC_NAME, |view: &mut SliderView| { view.get_value() }) {
            Some(v) => v,
            None => { show_message(s, "Unable to determine security level"); return }
        };

        let new_pw: String;

        {
            let generator_map: &mut HashMap<GenerationStrategy, Box<dyn PasswordGenerator>> = &mut state_for_gen_pw.borrow_mut().pw_gens;
            
            let generator: &mut Box<dyn PasswordGenerator> = match generator_map.get_mut(&strategy_group.selection()) {
                None => { show_message(s, "Unable create generator"); return },
                Some(g) => g
            };
    
            new_pw = match generator.gen_password(rand_bytes + 1) {
                Some(pw) => pw,
                None => {
                    show_message(s, "Unable to generate password"); 
                    return;
                }
            };
        }

        insert_into_entry(s, new_pw);
        s.pop_layer();        
    })
    .button("Cancel", |s| { s.pop_layer(); });
    
    s.add_layer(res);
    show_sec_bits(s, sec_bits);
}
