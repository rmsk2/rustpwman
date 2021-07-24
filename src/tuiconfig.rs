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
use cursive::views::{Dialog, LinearLayout, TextView, EditView, SelectView, TextArea, Panel, SliderView, RadioGroup, RadioButton};
use cursive::Cursive;
use cursive::event::EventResult;
use cursive::menu::MenuTree;
use cursive::align::HAlign;
use cursive::event::Key;

use crate::tomlconfig::RustPwManSerialize;
use crate::pwgen;
use crate::fcrypt;


pub fn config_main(config_file: std::path::PathBuf, sec_level: usize, pw_gen_strategy: pwgen::GenerationStrategy, pbkdf_id: fcrypt::KdfId) {
    let mut siv = cursive::default();

    siv.add_layer(
        Dialog::text("Not yet implemented")
            .title("Rustpwman")
            .button("Ok", |s| {
                s.pop_layer();
                s.quit();
            })
    );

    siv.run();
}