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

use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, TextView, TextArea, SliderView, RadioGroup};
use cursive::Cursive;
//use cursive::event::EventResult;

use crate::tomlconfig;
use crate::tomlconfig::RustPwManSerialize;
use crate::pwgen;
use crate::fcrypt;
use crate::modtui;

const BITS_SEC_VALUE: &str = "cfgseclevel";
const SLIDER_SEC_NAME: &str = "cfgslider";

fn show_yes_no_decision(siv: &mut Cursive, msg: &str) {
    siv.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Yes", move |s: &mut Cursive| {
                s.pop_layer();
                s.quit();
            })
            .button("No", |s| {
                s.pop_layer();
            })           
    );    
}

fn show_message(siv: &mut Cursive, msg: &str) {
    siv.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Ok", |s| {
                s.pop_layer();
            }),
    );
}

fn show_sec_bits(s: &mut Cursive, val: usize) {
    s.call_on_name(BITS_SEC_VALUE, |view: &mut TextArea| {
        let out = format!("{}", (val + 1) * 8);
        view.set_content(out.clone());
    });
}

pub fn config_main(config_file: std::path::PathBuf, sec_level: usize, pw_gen_strategy: pwgen::GenerationStrategy, pbkdf_id: fcrypt::KdfId) {
    let mut siv = cursive::default();

    let mut strategy_group: RadioGroup<pwgen::GenerationStrategy> = RadioGroup::new();
    let mut pbkdf_group: RadioGroup<fcrypt::KdfId> = RadioGroup::new();

    let mut linear_layout_pw_gen = LinearLayout::horizontal()
        .child(TextView::new("Contained characters: "));

    let mut linear_layout_pbkdf = LinearLayout::horizontal()
        .child(TextView::new("Key derivation function: "));  
        
    for i in &pwgen::GenerationStrategy::get_known_ids() {
        let mut b = strategy_group.button(*i, i.to_str());

        if *i == pw_gen_strategy {
            b.select();
        }

        linear_layout_pw_gen.add_child(b);
        linear_layout_pw_gen.add_child(TextView::new(" "));
    }    
    
    for i in &fcrypt::KdfId::get_known_ids() {
        let mut b = pbkdf_group.button(*i, i.to_str());

        if *i == pbkdf_id {
            b.select();
        }

        linear_layout_pbkdf.add_child(b);
        linear_layout_pbkdf.add_child(TextView::new(" "));
    }     

    let res = Dialog::new()
    .title("Rustpwman change config")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please select new defaults for the following values.\n\n"))
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
            .child(SliderView::horizontal(modtui::PW_MAX_SEC_LEVEL)
                .value(sec_level)
                .on_change(|s, slider_val| { show_sec_bits(s, slider_val) })
                .with_name(SLIDER_SEC_NAME))
        )
        .child(TextView::new("\n"))
        .child(linear_layout_pw_gen)
        .child(TextView::new("\n"))
        .child(linear_layout_pbkdf)
    )
    .button("OK", move |s| {  
        let rand_bytes = match s.call_on_name(SLIDER_SEC_NAME, |view: &mut SliderView| { view.get_value() }) {
            Some(v) => v,
            None => { 
                show_message(s, "Unable to determine security level"); 
                return; 
            }
        };
        
        let strategy = &strategy_group.selection();
        let pbkdf = &pbkdf_group.selection();

        let new_config = RustPwManSerialize::new(rand_bytes, pbkdf.to_str(), strategy.to_str());

        match tomlconfig::save(&config_file, new_config) {
            Some(e) => {
                show_yes_no_decision(s, &format!("Config could not be saved: {:?}. Leave program?", e));
            },
            None => { 
                show_yes_no_decision(s, "Config successfully saved. Leave program?");
            }
        };   
    })
    .button("Cancel", |s| { s.quit(); });
    
    siv.add_layer(res);
    show_sec_bits(&mut siv, sec_level);

    siv.run();
}