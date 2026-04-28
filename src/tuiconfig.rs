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

use std::str;

use cursive::traits::*;
use cursive::views::{Dialog, LinearLayout, TextView, TextArea, SliderView, RadioGroup, EditView, Panel, PaddedView};
use cursive::Cursive;
use cursive::view::Margins;

use crate::tomlconfig;
use crate::tomlconfig::RustPwManSerialize;
use crate::pwgen;
use crate::fcrypt;
use crate::modtui;
use crate::modtui::show_message;
use crate::modtui::pwgenerate::show_sec_bits;
use crate::RustPwMan;
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
const EDIT_VIEWER_COMMAND: &str = "viewercmd";
#[cfg(feature = "writebackup")]
const EDIT_BACKUP_FILE: &str = "backupfile";
#[cfg(feature = "webdav")]
const EDIT_WEBDAV_USER: &str = "webdav_user";
#[cfg(feature = "webdav")]
const EDIT_WEBDAV_PASSWORD: &str = "webdav_password";
#[cfg(feature = "webdav")]
const EDIT_WEBDAV_SERVER: &str = "webdav_server";


#[cfg(not(feature = "chacha20"))]
const CHACHA20:bool = false;
#[cfg(feature = "chacha20")]
const CHACHA20:bool = true;
#[cfg(not(feature = "qrcode"))]
const QR_CODE: bool = false;
#[cfg(feature = "qrcode")]
const QR_CODE: bool = true;

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

#[cfg(feature = "webdav")]
pub fn obfuscate_password(s: &mut Cursive) {
    if !is_obfuscation_possible(OBFUSCATION_ENV_VAR) {
        show_message(s, "Unable to obfuscate password");
    }

    let mut pw: String;

    if let Some(t) = s.call_on_name(EDIT_WEBDAV_PASSWORD, |view: &mut EditView| { view.get_content() }) {
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

    s.call_on_name(EDIT_WEBDAV_PASSWORD, |view: &mut EditView| { view.set_content(pw) });
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct OptionalConfigEntries {
    webdav_user: String,
    webdav_password: String,
    webdav_server: String,
    viewer_command: Option<String>,
    bkp_file_name: Option<String>,
}

macro_rules! get_string_value_from_ui {
    ($s:expr, $var:ident, $ui_name:expr, $msg:expr) => {
    let $var = match $s.call_on_name($ui_name, |view: &mut EditView| { view.get_content() }) {
        Some(v) => v,
        None => {
            show_message($s, $msg);
            return;
        }
    };
    }
}

#[cfg(feature = "webdav")]
macro_rules! get_string_value_from_ui_no_shadow {
    ($s:expr, $var:ident, $ui_name:expr, $msg:expr) => {
    $var = match $s.call_on_name($ui_name, |view: &mut EditView| { view.get_content() }) {
        Some(v) => v.to_string(),
        None => {
            show_message($s, $msg);
            return;
        }
    };
    }
}

#[allow(unused_variables)]
pub fn save_new_config(s: &mut Cursive, old_values: Box<OptionalConfigEntries>, config_file: &std::path::PathBuf, strat: &RadioGroup<pwgen::GenerationStrategy>, pbkdf: &RadioGroup<fcrypt::KdfId>, cipher: &RadioGroup<fcrypt::CipherId>) {
    // Use old values as a default. Overwrite them if new values were supplied
    #[allow(unused_mut, unused_assignments)]
    let mut user = old_values.webdav_user;
    #[allow(unused_mut, unused_assignments)]
    let mut pw = old_values.webdav_password;
    #[allow(unused_mut, unused_assignments)]
    let mut server = old_values.webdav_server;
    #[allow(unused_mut, unused_assignments)]
    let mut viewer_command = old_values.viewer_command;
    #[allow(unused_mut, unused_assignments)]
    let mut backup_file_name = old_values.bkp_file_name;

    // Read value of slider which represents the selected security level
    let rand_bytes = match s.call_on_name(SLIDER_SEC_NAME, |view: &mut SliderView| { view.get_value() }) {
        Some(v) => v,
        None => {
            show_message(s, "Unable to determine security level");
            return;
        }
    };

    // Read helper command for pasting the clipboard contents
    get_string_value_from_ui!(s, clip_command, EDIT_PASTE_COMMAND, "Unable to determine paste command");
    // Read helper command for writing to clipboard
    get_string_value_from_ui!(s, copy_command, EDIT_COPY_COMMAND, "Unable to determine copy command");

    #[cfg(feature = "qrcode")]
    {
        // Read helper command for viewing pictures
        get_string_value_from_ui!(s, viewer_command_txt, EDIT_VIEWER_COMMAND, "Unable to determine image viewer command");

        if viewer_command_txt.len() != 0 {
            viewer_command = Some(String::from(viewer_command_txt.as_str()));
        } else {
            viewer_command = None;
        }
    }

    #[cfg(feature = "writebackup")]
    {
        // Read name of file in which a backup of the current password data is stored
        get_string_value_from_ui!(s, backup_file_name_txt, EDIT_BACKUP_FILE, "Unable to determine backup file name");

        if backup_file_name_txt.len() != 0 {
            backup_file_name = Some(String::from(backup_file_name_txt.as_str()));
        } else {
            backup_file_name = None;
        }
    }


    // Read WebDAV user name
    #[cfg(feature = "webdav")]
    get_string_value_from_ui_no_shadow!(s, user, EDIT_WEBDAV_USER, "Unable to determine WebDAV user");
    // Read WebDAV password
    #[cfg(feature = "webdav")]
    get_string_value_from_ui_no_shadow!(s, pw, EDIT_WEBDAV_PASSWORD, "Unable to determine WebDAV password");
    // Read WebDAV server name
    #[cfg(feature = "webdav")]
    get_string_value_from_ui_no_shadow!(s, server, EDIT_WEBDAV_SERVER, "Unable to determine WebDAV server");

    // Read selected password generation strategy
    let strategy = strat.selection();
    // Read selected PBKDF
    let pbkdf = pbkdf.selection();
    let cipher_id: Option<String>;

    if !CHACHA20 {
        cipher_id = None;
    } else {
        // Read selected cipher
        cipher_id = Some(String::from(cipher.selection().to_str()));
    }

    // Write new config
    let new_config = RustPwManSerialize::new(rand_bytes, pbkdf.to_str(), strategy.to_str(), clip_command.as_str(), copy_command.as_str(), user.as_str(), pw.as_str(), server.as_str(), viewer_command, backup_file_name, cipher_id);

    match tomlconfig::save(config_file, new_config) {
        Some(e) => {
            show_yes_no_decision(s, &format!("Config could not be saved: {:?}. Leave program?", e));
        },
        None => {
            show_yes_no_decision(s, "Config successfully saved. Leave program?");
        }
    };
}

fn create_cipher_selection_ui(cipher_id: fcrypt::CipherId) -> (LinearLayout, RadioGroup<fcrypt::CipherId>) {
    let mut cipher_group: RadioGroup<fcrypt::CipherId> = RadioGroup::new();

    let mut linear_layout_cipher = LinearLayout::horizontal()
        .child(TextView::new("Encryption algorithm   : "));

    for i in &fcrypt::CipherId::get_known_ids() {
        let mut b = cipher_group.button(*i, i.to_str());

        if *i == cipher_id {
            b.select();
        }

        linear_layout_cipher.add_child(b);
        linear_layout_cipher.add_child(TextView::new(" "));
    }

    return (linear_layout_cipher, cipher_group);
}

fn create_pbkdf_selection_ui(pbkdf_id: fcrypt::KdfId) -> (LinearLayout, RadioGroup<fcrypt::KdfId>) {
    let mut pbkdf_group: RadioGroup<fcrypt::KdfId> = RadioGroup::new();

    let mut linear_layout_pbkdf = LinearLayout::horizontal()
        .child(TextView::new("Key derivation function: "));

    for i in &fcrypt::KdfId::get_known_ids() {
        let mut b = pbkdf_group.button(*i, i.to_str());

        if *i == pbkdf_id {
            b.select();
        }

        linear_layout_pbkdf.add_child(b);
        linear_layout_pbkdf.add_child(TextView::new(" "));
    }

    return (linear_layout_pbkdf, pbkdf_group);
}

fn create_pw_gen_strategy_selection_ui(pw_gen_strategy: pwgen::GenerationStrategy) -> (LinearLayout, RadioGroup<pwgen::GenerationStrategy>) {
    let mut strategy_group: RadioGroup<pwgen::GenerationStrategy> = RadioGroup::new();

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

    return (linear_layout_pw_gen, strategy_group);    
}

fn create_command_selection_ui() -> Panel<PaddedView<LinearLayout>> {
    let mut cmds_layout = LinearLayout::vertical();
    cmds_layout.add_child(LinearLayout::horizontal()
        .child(TextView::new("Paste command       : "))
        .child(EditView::new()
            .with_name(EDIT_PASTE_COMMAND)
            .fixed_width(60))
    );

    cmds_layout.add_child(TextView::new("\n"));

    cmds_layout.add_child(LinearLayout::horizontal()
        .child(TextView::new("Copy command        : "))
        .child(EditView::new()
            .with_name(EDIT_COPY_COMMAND)
            .fixed_width(60)));

    if QR_CODE {
        let viewer_select = LinearLayout::horizontal()
                .child(TextView::new("Image viewer command: "))
                .child(EditView::new()
                    .with_name(EDIT_VIEWER_COMMAND)
                    .fixed_width(60));

        cmds_layout.add_child(TextView::new("\n"));
        cmds_layout.add_child(viewer_select);
    }

    return Panel::new(PaddedView::new(Margins::lrtb(1,1,1,1), cmds_layout)).title("Helper commands")
}

#[cfg(feature = "writebackup")]
fn create_writebackup_ui() -> Panel<PaddedView<LinearLayout>> {
    return Panel::new(
        PaddedView::new(Margins::lrtb(1,1,1,1),
            LinearLayout::horizontal()
                .child(TextView::new("Filename: "))
                .child(EditView::new()
                    .with_name(EDIT_BACKUP_FILE)
                    .fixed_width(65))
        )
    )
    .title("Name of file to use for automatic backup")
}

#[cfg(feature = "writebackup")]
fn set_write_backup_state(siv: &mut Cursive, bkp_f: &Option<String>) {
    let bkp_f_helper = bkp_f.clone();

    if let Some(bkp) = bkp_f_helper {
        siv.call_on_name(EDIT_BACKUP_FILE, |view: &mut EditView| { view.set_content(bkp.clone()) });
    } else {
        siv.call_on_name(EDIT_BACKUP_FILE, |view: &mut EditView| { view.set_content(String::from("")) });
    }
}

#[cfg(feature = "webdav")]
fn create_wbdav_ui() -> Panel<PaddedView<LinearLayout>> {
    return Panel::new(
        PaddedView::new(Margins::lrtb(1,1,1,1),
        LinearLayout::vertical()
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("User-ID : "))
                .child(EditView::new()
                    .with_name(EDIT_WEBDAV_USER)
                    .fixed_width(65))
        )
        .child(TextView::new("\n"))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("Password: "))
                .child(EditView::new()
                    .with_name(EDIT_WEBDAV_PASSWORD)
                    .fixed_width(65))
        )
        .child(TextView::new("\n"))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("Server  : "))
                .child(EditView::new()
                    .with_name(EDIT_WEBDAV_SERVER)
                    .fixed_width(65)))
        )
    )
    .title("WebDAV parameters");
}

#[cfg(feature = "webdav")]
fn set_webdav_state(siv: &mut Cursive, webdav_user: &String, webdav_server: &String, webdav_pw: &String) {
    siv.call_on_name(EDIT_WEBDAV_USER, |view: &mut EditView| { view.set_content(webdav_user) });
    siv.call_on_name(EDIT_WEBDAV_PASSWORD, |view: &mut EditView| { view.set_content(webdav_pw) });
    siv.call_on_name(EDIT_WEBDAV_SERVER, |view: &mut EditView| { view.set_content(webdav_server) });

}

#[cfg(feature = "qrcode")]
fn set_qrcode_state(siv: &mut Cursive, viewer_cmd: &Option<String>) {
    if let Some(vc) = viewer_cmd {
        siv.call_on_name(EDIT_VIEWER_COMMAND, |view: &mut EditView| { view.set_content(vc.clone()) });
    } else {
        siv.call_on_name(EDIT_VIEWER_COMMAND, |view: &mut EditView| { view.set_content(String::from("")) });
    }
}

fn create_pw_strategy_select_ui(sec_level: usize, linear_layout_pw_gen: LinearLayout) -> Panel<PaddedView<LinearLayout>> {
    return Panel::new(
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
            .on_change(|s, slider_val| { show_sec_bits(s, slider_val, BITS_SEC_VALUE) })
            .with_name(SLIDER_SEC_NAME))
        )
        .child(TextView::new("\n"))
        .child(linear_layout_pw_gen)
        ))
        .title("Parameters for password generation");
}

fn create_algo_select_ui(linear_layout_pbkdf: LinearLayout, cipher_select: LinearLayout) -> Panel<PaddedView<LinearLayout>> {
    let mut lin = LinearLayout::vertical();
    
    lin.add_child(linear_layout_pbkdf);

    if CHACHA20 {
        lin.add_child(TextView::new("\n"));
        lin.add_child(cipher_select);
    }

    return Panel::new(PaddedView::new(Margins::lrtb(1,1,1,1),lin)).title("Default crypto algorithms");
}

fn set_clip_commands_state(siv: &mut Cursive, clp_cmd: &String, cpy_cmd: &String) {
    siv.call_on_name(EDIT_PASTE_COMMAND, |view: &mut EditView| { view.set_content(clp_cmd) });
    siv.call_on_name(EDIT_COPY_COMMAND, |view: &mut EditView| { view.set_content(cpy_cmd) });
}

#[allow(unused_variables)]
pub fn config_main(app: &RustPwMan, config_file: std::path::PathBuf, sec_level: usize, pw_gen_strategy: pwgen::GenerationStrategy, pbkdf_id: fcrypt::KdfId,
                   clp_cmd: &String, cpy_cmd: &String, webdav_user: &String, webdav_pw: &String, webdav_server: &String, viewer_cmd: &Option<String>, cipher_id: fcrypt::CipherId) {
    // Construct UI
    let mut siv = cursive::default();

    // Create radio groups for password generation strategy and crypto algorithms
    let (linear_layout_pw_gen, strategy_group) = create_pw_gen_strategy_selection_ui(pw_gen_strategy);
    let (linear_layout_pbkdf, pbkdf_group) = create_pbkdf_selection_ui(pbkdf_id);
    let (linear_layout_cipher, cipher_group) = create_cipher_selection_ui(cipher_id);

    // Create panels for pw generation strategy, crypto algorithms, helper commands, backup file selection and WebDAV parameters
    let mut config_panels = LinearLayout::vertical();
    config_panels.add_child(create_pw_strategy_select_ui(sec_level, linear_layout_pw_gen));
    config_panels.add_child(create_algo_select_ui(linear_layout_pbkdf, linear_layout_cipher));
    config_panels.add_child(create_command_selection_ui());    
    #[cfg(feature = "writebackup")]
    config_panels.add_child(create_writebackup_ui());
    #[cfg(feature = "webdav")]
    config_panels.add_child(create_wbdav_ui());

    let title_str = match config_file.as_os_str().to_str() {
        Some(s) => s,
        None => {
            "File name not UTF-8"
        }
    };

    // Assemble components in one Dialog
    let title_string = format!("Change config {}", title_str);

    let mut res = Dialog::new()
    .title(title_string)
    .padding_lrtb(2, 2, 1, 1)
    .content(
        config_panels
    );

    let old_values = OptionalConfigEntries {
        webdav_user: webdav_user.clone(),
        webdav_password: webdav_pw.clone(),
        webdav_server: webdav_server.clone(),
        viewer_command: viewer_cmd.clone(),
        bkp_file_name: app.get_backup_file_name_str(),
    };

    let bkp_file_name = old_values.bkp_file_name.clone();

    res.add_button("OK", move |s| save_new_config(s, Box::new(old_values.clone()), &config_file, &strategy_group, &pbkdf_group, &cipher_group));
    res.add_button("Cancel", |s| s.quit() );
    #[cfg(feature = "webdav")]
    res.add_button("Obfuscate", move |s| obfuscate_password(s));

    siv.add_layer(res);
    
    // Set state of UI elements to values which reflect the current config
    show_sec_bits(&mut siv, sec_level, BITS_SEC_VALUE);
    set_clip_commands_state(&mut siv, clp_cmd, cpy_cmd);
    #[cfg(feature = "writebackup")]
    set_write_backup_state(&mut siv, &bkp_file_name);
    #[cfg(feature = "webdav")]
    set_webdav_state(&mut siv, webdav_user, webdav_server, webdav_pw);
    #[cfg(feature = "qrcode")]
    set_qrcode_state(&mut siv, viewer_cmd);

    crate::load_theme!(siv);

    siv.run();
}
