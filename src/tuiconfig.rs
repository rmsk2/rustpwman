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
use crate::pwgen::StrGetter;
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

#[cfg(any(feature = "writebackup", feature = "qrcode"))]
fn to_option(str: &String) -> Option<String> {
    if str.len() != 0 {
        return Some(String::from(str.as_str()));
    } else {
        return None;
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
    let clip_command: String;
    get_string_value_from_ui_no_shadow!(s, clip_command, EDIT_PASTE_COMMAND, "Unable to determine paste command");
    // Read helper command for writing to clipboard
    let copy_command: String;
    get_string_value_from_ui_no_shadow!(s, copy_command, EDIT_COPY_COMMAND, "Unable to determine copy command");

    #[cfg(feature = "qrcode")]
    {
        // Read helper command for viewing pictures
        let viewer_command_txt: String;
        get_string_value_from_ui_no_shadow!(s, viewer_command_txt, EDIT_VIEWER_COMMAND, "Unable to determine image viewer command");
        viewer_command = to_option(&viewer_command_txt);
    }

    #[cfg(feature = "writebackup")]
    {
        // Read name of file in which a backup of the current password data is stored
        let backup_file_name_txt: String;
        get_string_value_from_ui_no_shadow!(s, backup_file_name_txt, EDIT_BACKUP_FILE, "Unable to determine backup file name");
        backup_file_name = to_option(&backup_file_name_txt);
    }

    // Read WebDAV user name
    #[cfg(feature = "webdav")]
    {
        get_string_value_from_ui_no_shadow!(s, user, EDIT_WEBDAV_USER, "Unable to determine WebDAV user");
        get_string_value_from_ui_no_shadow!(s, pw, EDIT_WEBDAV_PASSWORD, "Unable to determine WebDAV password");
        get_string_value_from_ui_no_shadow!(s, server, EDIT_WEBDAV_SERVER, "Unable to determine WebDAV server");
    }

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

fn create_algo_selection_ui<T: Send + Sync + Eq + StrGetter+ 'static + Copy>(algo_id: T, msg: &str) -> (LinearLayout, RadioGroup<T>) {
    let mut algo_group: RadioGroup<T> = RadioGroup::new();

    let mut linear_layout_cipher = LinearLayout::horizontal()
        .child(TextView::new(msg));

    for i in &algo_id.get_all_ids() {
        let mut b = algo_group.button(*i, i.to_str());

        if *i == algo_id {
            b.select();
        }

        linear_layout_cipher.add_child(b);
        linear_layout_cipher.add_child(TextView::new(" "));
    }

    return (linear_layout_cipher, algo_group);
}

fn create_edit_field_with_label(label: &str, name: &str, size: usize) -> LinearLayout {
    return LinearLayout::horizontal()
        .child(TextView::new(label))
        .child(EditView::new()
            .with_name(name)
            .fixed_width(size))
}

fn create_command_selection_ui() -> Panel<PaddedView<LinearLayout>> {
    let mut cmds_layout = LinearLayout::vertical();
    cmds_layout.add_child(create_edit_field_with_label("Paste command       : ", EDIT_PASTE_COMMAND, 60));
    cmds_layout.add_child(TextView::new("\n"));
    cmds_layout.add_child(create_edit_field_with_label("Copy command        : ", EDIT_COPY_COMMAND, 60));

    if QR_CODE {
        cmds_layout.add_child(TextView::new("\n"));
        cmds_layout.add_child(create_edit_field_with_label("Image viewer command: ", EDIT_VIEWER_COMMAND, 60));
    }

    return Panel::new(PaddedView::new(Margins::lrtb(1,1,1,1), cmds_layout)).title("Helper commands")
}

#[cfg(feature = "writebackup")]
fn create_writebackup_ui() -> Panel<PaddedView<LinearLayout>> {
    return Panel::new(
        PaddedView::new(Margins::lrtb(1,1,1,1),
            create_edit_field_with_label("Filename: ", EDIT_BACKUP_FILE, 65)
        )
    )
    .title("Name of file to use for automatic backup")
}


#[cfg(any(feature = "writebackup", feature = "qrcode"))]
fn set_edit_state_by_option(siv: &mut Cursive, name: &str, data: &Option<String>) {
    if let Some(d) = data {
        siv.call_on_name(name, |view: &mut EditView| { view.set_content(d.clone()) });
    } else {
        siv.call_on_name(name, |view: &mut EditView| { view.set_content(String::from("")) });
    }
}

#[cfg(feature = "webdav")]
fn create_webdav_ui() -> Panel<PaddedView<LinearLayout>> {
    return Panel::new(
        PaddedView::new(Margins::lrtb(1,1,1,1),
        LinearLayout::vertical()
        .child(create_edit_field_with_label("User-ID : ", EDIT_WEBDAV_USER, 65))
        .child(TextView::new("\n"))
        .child(create_edit_field_with_label("Password: ", EDIT_WEBDAV_PASSWORD, 65))
        .child(TextView::new("\n"))
        .child(create_edit_field_with_label("Server  : ", EDIT_WEBDAV_SERVER, 65))
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
    let (linear_layout_pw_gen, strategy_group) = create_algo_selection_ui(pw_gen_strategy, "Contained characters: ");
    let (linear_layout_pbkdf, pbkdf_group) = create_algo_selection_ui(pbkdf_id, "Key derivation function: ");
    let (linear_layout_cipher, cipher_group) = create_algo_selection_ui(cipher_id, "Encryption algorithm   : ");

    // Create panels for pw generation strategy, crypto algorithms, helper commands, backup file selection and WebDAV parameters
    let mut config_panels = LinearLayout::vertical();

    config_panels.add_child(create_pw_strategy_select_ui(sec_level, linear_layout_pw_gen));
    config_panels.add_child(create_algo_select_ui(linear_layout_pbkdf, linear_layout_cipher));
    config_panels.add_child(create_command_selection_ui());    
    #[cfg(feature = "writebackup")]
    config_panels.add_child(create_writebackup_ui());
    #[cfg(feature = "webdav")]
    config_panels.add_child(create_webdav_ui());

    let title_str = match config_file.as_os_str().to_str() {
        Some(s) => s,
        None => {
            "File name not UTF-8"
        }
    };

    // Assemble components in one Dialog
    let mut res = Dialog::new()
        .title(format!("Change config {}", title_str))
        .padding_lrtb(2, 2, 1, 1)
        .content(config_panels);

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
    set_edit_state_by_option(&mut siv, EDIT_BACKUP_FILE, &bkp_file_name);
    #[cfg(feature = "webdav")]
    set_webdav_state(&mut siv, webdav_user, webdav_server, webdav_pw);
    #[cfg(feature = "qrcode")]
    set_edit_state_by_option(&mut siv, EDIT_VIEWER_COMMAND, viewer_cmd);

    crate::load_theme!(siv);

    siv.run();
}
