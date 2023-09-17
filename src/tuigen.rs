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

use std::cell::Cell;
use std::rc::Rc;
use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, TextView, TextArea, SliderView, RadioGroup, DialogFocus};
use cursive::Cursive;


use crate::pwgen;
use crate::modtui;
use crate::tuiconfig;

const GEN_BITS_SEC_VALUE: &str = "genseclevel";
const GEN_SLIDER_SEC_NAME: &str = "genslider";
const GEN_SLIDER_NUM_PW_NAME: &str = "genslidernumpw";
const GEN_NUM_PW_VALUE: &str = "gennumpwval";
const GEN_DIALOG: &str = "pwgendialog";
const MAX_NUM_PASSWORDS: usize = 16;
const NUM_PW_DEFAULT: usize = 0;

fn show_sec_bits(s: &mut Cursive, val: usize) {
    s.call_on_name(GEN_BITS_SEC_VALUE, |view: &mut TextArea| {
        let out = format!("{}", (val + 1) * 8);
        view.set_content(out.clone());
    });
}

fn show_num_pws(s: &mut Cursive, val: usize) {
    s.call_on_name(GEN_NUM_PW_VALUE, |view: &mut TextArea| {
        let out = format!("{}", val+1);
        view.set_content(out.clone());
    });
}


pub fn generate_main(sec_level: usize, pw_gen_strategy: pwgen::GenerationStrategy) {
    let mut siv = cursive::default();
    let mut strategy_group: RadioGroup<pwgen::GenerationStrategy> = RadioGroup::new();

    let selected_sec_level = Rc::new(Cell::new(sec_level));
    let selected_strategy = Rc::new(Cell::new(pw_gen_strategy));
    let selected_num_pws = Rc::new(Cell::new(NUM_PW_DEFAULT));

    let level = selected_sec_level.clone();
    let strategy = selected_strategy.clone();
    let num_pws = selected_num_pws.clone();

    let mut linear_layout_pw_gen = LinearLayout::horizontal()
        .child(TextView::new("Contained characters: "));
        
    for i in &pwgen::GenerationStrategy::get_known_ids() {
        let mut b = strategy_group.button(*i, i.to_str());

        if *i == pw_gen_strategy {
            b.select();
        }

        linear_layout_pw_gen.add_child(b);
        linear_layout_pw_gen.add_child(TextView::new(" "));
    }         

    let res = Dialog::new()
    .title("Rustpwman generate passwords")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please select generation parameters.\n\n"))
        .child(TextView::new("\n"))
        .child(LinearLayout::horizontal()
            .child(TextView::new("Security level "))
            .child(TextArea::new()
                .content("")
                .disabled()
                .with_name(GEN_BITS_SEC_VALUE)
                .fixed_height(1)
                .fixed_width(4)
            )            
            .child(TextView::new("Bits: "))
            .child(SliderView::horizontal(modtui::PW_MAX_SEC_LEVEL)
                .value(sec_level)
                .on_change(|s, slider_val| { show_sec_bits(s, slider_val) })
                .with_name(GEN_SLIDER_SEC_NAME))
        )
        .child(TextView::new("\n"))
        .child(linear_layout_pw_gen)
        .child(TextView::new("\n"))
        .child(LinearLayout::horizontal()
            .child(TextView::new("Number of passwords to generate: "))
            .child(TextArea::new()
                .content("")
                .disabled()
                .with_name(GEN_NUM_PW_VALUE)
                .fixed_height(1)
                .fixed_width(4)
            )            
            .child(SliderView::horizontal(MAX_NUM_PASSWORDS)
                .value(NUM_PW_DEFAULT)
                .on_change(|s, slider_val| { show_num_pws(s, slider_val) })
                .with_name(GEN_SLIDER_NUM_PW_NAME))
        )        
    )
    .button("OK", move |s| {  
        let h = match s.call_on_name(GEN_SLIDER_SEC_NAME, |view: &mut SliderView| { view.get_value() }) {
            Some(v) => v,
            None => { 
                tuiconfig::show_message(s, "Unable to determine security level"); 
                return; 
            }
        };

        let h3 = match s.call_on_name(GEN_SLIDER_NUM_PW_NAME, |view: &mut SliderView| { view.get_value() }) {
            Some(v) => v,
            None => { 
                tuiconfig::show_message(s, "Unable to determine number of passwords to generate"); 
                return; 
            }
        };        

        level.replace(h);
        num_pws.replace(h3);

        let h2 = *(&strategy_group.selection()).clone();
        strategy.replace(h2);
        
        s.pop_layer();
        s.quit();
    })
    .button("Cancel", |s| { s.quit(); })
    .with_name(GEN_DIALOG);
    
    siv.add_layer(res);
    show_sec_bits(&mut siv, sec_level);
    show_num_pws(&mut siv, NUM_PW_DEFAULT);
    siv.call_on_name(GEN_DIALOG, |view: &mut Dialog| {view.set_focus(DialogFocus::Button(0))});

    siv.run();

    let mut generator = selected_strategy.get().to_creator()();

    for _n in 0..selected_num_pws.get()+1 {
        let pw = match generator.gen_password(selected_sec_level.get()) {
            Some(s) => s,
            None => {eprintln!("Unable to generate password"); return;}
        };
        
        println!("{}", pw);        
    }
}