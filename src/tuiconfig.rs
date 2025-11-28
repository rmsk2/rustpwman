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
use cursive::views::{Dialog, LinearLayout, TextView, TextArea, SliderView, RadioGroup, EditView, Panel, PaddedView};
use cursive::Cursive;
use cursive::view::Margins;

use crate::tomlconfig;
use crate::tomlconfig::RustPwManSerialize;
use crate::pwgen;
use crate::fcrypt;
use crate::modtui;
use crate::tuiconfig;
#[cfg(feature = "webdav")]
use crate::OBFUSCATION_ENV_VAR;
#[cfg(feature = "webdav")]
use crate::obfuscate::is_obfuscated;
#[cfg(feature = "webdav")]
use crate::obfuscate::obfuscate;
#[cfg(feature = "webdav")]
use crate::obfuscate::is_obfuscation_possible;


const BITS_SEC_VALUE: &str = "cfgseclevel";
const SLIDER_SEC_NAME: &str = "cfgslider";
const EDIT_PASTE_COMMAND: &str = "pastecmd";
const EDIT_COPY_COMMAND: &str = "copycmd";
#[cfg(feature = "qrcode")]
const EDIT_VIEWER_COMMAND: &str = "viewercmd";

pub fn show_yes_no_decision(siv: &mut Cursive, msg: &str) {
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

pub fn show_message(siv: &mut Cursive, msg: &str) {
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

#[cfg(feature = "webdav")]
pub fn obfuscate_password(s: &mut Cursive) {
    if !is_obfuscation_possible(OBFUSCATION_ENV_VAR) {
        show_message(s, "Unable to obfuscate password");
    }

    let mut pw: String;

    if let Some(t) = s.call_on_name("webdav_password", |view: &mut EditView| { view.get_content() }) {
        pw = t.to_string();
    } else {
        show_message(s, "Unable to determine WebDAV password");
        return;
    }

    if is_obfuscated(&pw) {
        show_message(s, "Password already obfuscated");
        return;
    }

    pw = obfuscate(&pw, OBFUSCATION_ENV_VAR);

    s.call_on_name("webdav_password", |view: &mut EditView| { view.set_content(pw) });
}

pub fn save_new_config(s: &mut Cursive, u: &String, p: &String, srv: &String, config_file: &std::path::PathBuf, strat: &RadioGroup<pwgen::GenerationStrategy>, pbkdf: &RadioGroup<fcrypt::KdfId>, vwr: &Option<String>) {
    #[allow(unused_mut, unused_assignments)]
    let mut user = u.clone();
    #[allow(unused_mut, unused_assignments)]
    let mut pw = p.clone();
    #[allow(unused_mut, unused_assignments)]
    let mut server = srv.clone();
    #[allow(unused_mut, unused_assignments)]
    let mut viewer_command = vwr.clone();

    let rand_bytes = match s.call_on_name(SLIDER_SEC_NAME, |view: &mut SliderView| { view.get_value() }) {
        Some(v) => v,
        None => {
            show_message(s, "Unable to determine security level");
            return;
        }
    };

    let clip_command = match s.call_on_name(EDIT_PASTE_COMMAND, |view: &mut EditView| { view.get_content() }) {
        Some(v) => v,
        None => {
            show_message(s, "Unable to determine paste command");
            return;
        }
    };

    let copy_command = match s.call_on_name(EDIT_COPY_COMMAND, |view: &mut EditView| { view.get_content() }) {
        Some(v) => v,
        None => {
            show_message(s, "Unable to determine copy command");
            return;
        }
    };

    #[cfg(feature = "qrcode")]
    {
        let viewer_command_txt = match s.call_on_name(EDIT_VIEWER_COMMAND, |view: &mut EditView| { view.get_content() }) {
            Some(v) => v,
            None => {
                show_message(s, "Unable to determine image viewer command");
                return;
            }
        };

        if viewer_command_txt.len() != 0 {
            viewer_command = Some(String::from(viewer_command_txt.as_str()));
        } else {
            viewer_command = None;
        }
    }


    #[cfg(feature = "webdav")]
    if let Some(t) = s.call_on_name("webdav_user", |view: &mut EditView| { view.get_content() }) {
        user = t.to_string();
    } else {
        show_message(s, "Unable to determine WebDAV user");
        return;
    }

    #[cfg(feature = "webdav")]
    if let Some(t) = s.call_on_name("webdav_password", |view: &mut EditView| { view.get_content() }) {
        pw = t.to_string();
    } else {
        show_message(s, "Unable to determine WebDAV password");
        return;
    }

    #[cfg(feature = "webdav")]
    if let Some(t) = s.call_on_name("webdav_server", |view: &mut EditView| { view.get_content() }) {
        server = t.to_string();
    } else {
        show_message(s, "Unable to determine WebDAV server");
        return;
    }

    let strategy = strat.selection();
    let pbkdf = &pbkdf.selection();

    let new_config = RustPwManSerialize::new(rand_bytes, pbkdf.to_str(), strategy.to_str(), clip_command.as_str(), copy_command.as_str(), user.as_str(), pw.as_str(), server.as_str(), viewer_command);

    match tomlconfig::save(config_file, new_config) {
        Some(e) => {
            show_yes_no_decision(s, &format!("Config could not be saved: {:?}. Leave program?", e));
        },
        None => {
            show_yes_no_decision(s, "Config successfully saved. Leave program?");
        }
    };
}

pub fn config_main(config_file: std::path::PathBuf, sec_level: usize, pw_gen_strategy: pwgen::GenerationStrategy, pbkdf_id: fcrypt::KdfId,
                   clp_cmd: &String, cpy_cmd: &String, webdav_user: &String, webdav_pw: &String, webdav_server: &String, viewer_cmd: &Option<String>) {
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

    let mut config_panels = LinearLayout::vertical();

    config_panels.add_child(Panel::new(
        PaddedView::new(Margins::lrtb(1,1,1,1),
        LinearLayout::vertical()
        .child(
        LinearLayout::horizontal()
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
        ))
        .title("Parameters for password generation")
    );

    config_panels.add_child(
        Panel::new(
            PaddedView::new(Margins::lrtb(1,1,1,1),
                linear_layout_pbkdf)
            ).title("Default PBKDF")
    );

    let mut cmds_layout =LinearLayout::vertical();
    cmds_layout.add_child(LinearLayout::horizontal()
        .child(TextView::new("Paste command        : "))
        .child(EditView::new()
            .with_name(EDIT_PASTE_COMMAND)
            .fixed_width(60))
    );

    cmds_layout.add_child(TextView::new("\n"));

    cmds_layout.add_child(LinearLayout::horizontal()
        .child(TextView::new("Copy command         : "))
        .child(EditView::new()
            .with_name(EDIT_COPY_COMMAND)
            .fixed_width(60)));

    #[cfg(feature = "qrcode")]
    {
        cmds_layout.add_child(TextView::new("\n"));
        cmds_layout.add_child(LinearLayout::horizontal()
            .child(TextView::new("Image viewer command : "))
            .child(EditView::new()
                .with_name(EDIT_VIEWER_COMMAND)
                .fixed_width(60)));

    }

    config_panels.add_child(
        Panel::new(
            PaddedView::new(Margins::lrtb(1,1,1,1), cmds_layout))
            .title("Helper commands")
    );

    #[cfg(feature = "webdav")]
    {
        config_panels.add_child(
            Panel::new(
                PaddedView::new(Margins::lrtb(1,1,1,1),
                LinearLayout::vertical()
                .child(
                    LinearLayout::horizontal()
                        .child(TextView::new("User-ID : "))
                        .child(EditView::new()
                            .with_name("webdav_user")
                            .fixed_width(65))
                )
                .child(TextView::new("\n"))
                .child(
                    LinearLayout::horizontal()
                        .child(TextView::new("Password: "))
                        .child(EditView::new()
                            .with_name("webdav_password")
                            .fixed_width(65))
                )
                .child(TextView::new("\n"))
                .child(
                    LinearLayout::horizontal()
                        .child(TextView::new("Server  : "))
                        .child(EditView::new()
                            .with_name("webdav_server")
                            .fixed_width(65))
                )
            )
        )
        .title("WebDAV parameters")
        );
    }

    let title_str = match config_file.as_os_str().to_str() {
        Some(s) => s,
        None => {
            "File name not UTF-8"
        }
    };

    let title_string = format!("Change config {}", title_str);

    let mut res = Dialog::new()
    .title(title_string)
    .padding_lrtb(2, 2, 1, 1)
    .content(
        config_panels
    );

    let u = webdav_user.clone();
    let p = webdav_pw.clone();
    let serv = webdav_server.clone();
    let vwr = viewer_cmd.clone();

    res.add_button("OK", move |s| save_new_config(s, &u, &p, &serv, &config_file, &strategy_group, &pbkdf_group, &vwr));
    res.add_button("Cancel", |s| s.quit() );

    #[cfg(feature = "webdav")]
    res.add_button("Obfuscate", move |s| obfuscate_password(s));

    siv.add_layer(res);
    show_sec_bits(&mut siv, sec_level);
    siv.call_on_name(EDIT_PASTE_COMMAND, |view: &mut EditView| { view.set_content(clp_cmd) });
    siv.call_on_name(EDIT_COPY_COMMAND, |view: &mut EditView| { view.set_content(cpy_cmd) });

    #[cfg(feature = "webdav")]
    {
        siv.call_on_name("webdav_user", |view: &mut EditView| { view.set_content(webdav_user) });
        siv.call_on_name("webdav_password", |view: &mut EditView| { view.set_content(webdav_pw) });
        siv.call_on_name("webdav_server", |view: &mut EditView| { view.set_content(webdav_server) });
    }

    #[cfg(feature = "qrcode")]
    {
        if let Some(vc) = viewer_cmd {
            siv.call_on_name(EDIT_VIEWER_COMMAND, |view: &mut EditView| { view.set_content(vc.clone()) });
        } else {
            siv.call_on_name(EDIT_VIEWER_COMMAND, |view: &mut EditView| { view.set_content(String::from("")) });
        }
    }

    match crate::modtui::tuitheme::get_theme() {
        Ok(theme) => siv.set_theme(theme),
        Err(e) => { 
            tuiconfig::show_message(&mut siv, format!("Error in theme.json:\n\n{}\n\nDefault theme will be used!", e).as_str()); 
        }
    }

    siv.run();
}
