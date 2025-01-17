/* Copyright 2025 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::Sender;

use cursive::Cursive;
use cursive::views::{Dialog, LinearLayout, TextView, EditView};
use cursive::traits::*;
#[cfg(feature = "pwmanclient")]
use super::cache;
#[cfg(feature = "pwmanclient")]
use crate::persist::SendSyncPersister;

use super::{main_window, AppState};
use super::pwman_quit;
use super::show_message;
use crate::jots;

const EDIT_OUT_NAME: &str = "outname";

const STYLE: &str = r#"
th,
td {
  border: 1px solid rgb(160 160 160);
  padding: 8px 10px;
}
tt.big {
  font-size: 18px;
}
td.big {
  font-size: 19px;
}
"#;

const HEADER_BEGIN: &str = r#"
<!DOCTYPE html>
<html>
<head>
"#;

const HEADER_END: &str = r#"
</head>
<body>
<table>
<tr>
<th>Application</th>
<th>Info and password</th>
</tr>
"#;

const FOOTER: &str = r#"
</table>
</body>
</html>
"#;

fn success_message(siv: &mut Cursive, msg: &str, shared_state: Arc<Mutex<AppState>>, sndr: Arc<Sender<String>>) {
    siv.add_layer(
        Dialog::text(msg)
            .title("Rustpwman")
            .button("Ok", move |siv| {
                siv.pop_layer();
                siv.pop_layer();
                //pwman_quit(s, sndr.clone(), String::from("")) 

                #[cfg(feature = "pwmanclient")]
                {
                    // Ensure that state.pw_is_chached is correct
                    let mut state = shared_state.lock().unwrap();
                    let pw_state = check_cached_password(&state.persister, &state.password);
                    state.pw_is_chached = pw_state;
                }

                main_window(siv, shared_state.clone(), sndr.clone());
            }),
    );
}

#[cfg(feature = "pwmanclient")]
fn check_cached_password(p: &SendSyncPersister, ref_pw: &Option<String>) -> bool {
    // At this point this operation should not fail
    let ref_pw = match ref_pw {
        Some(p) => p,
        None => {
            return false;
        }
    };
    
    // At this point this operation should not fail
    let store_id = match p.get_canonical_path() {
        Ok(s) => s,
        Err(_) => {
            return false;
        }
    };        

    // If there is no pwman client, then there is no cached password
    let pwman_client = match cache::make_pwman_client(store_id) {
        Ok(c) => {
            c
        },
        Err(_) => {                
            return false;
        }
    };

    // Make sure password found in state matches the one stored in pwman
    let pw_to_test = match pwman_client.get_password() {
        Ok(pw_to_test) => pw_to_test,
        Err(_) => {
            return false;
        }
    };

    return ref_pw == &pw_to_test;
}

fn create_html(data: &jots::Jots) -> String {
    let mut res = String::from("");
    res.push_str(HEADER_BEGIN);
    res.push_str(format!("<style>{}</style>", STYLE).as_str());
    res.push_str(HEADER_END);
    
    for key in data {
        let mut line = String::from("<tr>\n");

        let text = match data.get(key) {
            Some(t) => t,
            None => { return res }
        };

        line.push_str(format!("<td class=\"big\">{}</td>\n", key).as_str());

        let mut contents = text.clone();
        contents = contents.replace("\n", "</br>");
        contents = contents.replace(" ", "&nbsp");

        line.push_str(format!("<td><tt class=\"big\">{}</tt></td>\n", contents).as_str());
        line.push_str("</tr>\n");

        res.push_str(line.as_str());
    }

    res.push_str(FOOTER);

    return res;
}

pub fn window(s: &mut Cursive, shared_state: Arc<Mutex<AppState>>, sndr: Arc<Sender<String>>) {
    let sndr_ok = sndr.clone();
    let sndr_cancel = sndr.clone();

    let res = Dialog::new()
    .title("Rustpwman export contents")
    .padding_lrtb(2, 2, 1, 1)
    .content(
        LinearLayout::vertical()
        .child(TextView::new("Please enter file name for saving exported data.\n\n"))
        .child(
            LinearLayout::horizontal()
                .child(TextView::new("Filename: "))
                .child(EditView::new()
                    .with_name(EDIT_OUT_NAME)
                    .fixed_width(60))        
        )
    )
    .button("Export", move |s| {
        let file_name = match s.call_on_name(EDIT_OUT_NAME, |view: &mut EditView| { view.get_content() }) {
            Some(name) => {
                name.clone()
            },
            None => { show_message(s, "Unable to read file name"); return }
        }; 

        let data :String;

        // create artificial scope to ensure unlock of global state
        {
            let state = shared_state.lock().unwrap();
            data = create_html(&state.store);
        }

        // Create artificial scope to make sure file is dropped and thereby closed as early as possible
        {
            let mut f = match fs::File::create(&file_name.as_str()) {
                Ok(opened) => {
                    opened
                },
                Err(e) => { show_message(s, &format!("Unable to write file: {:?}", e)) ; return  }
            };
    
            match f.write_all(&data.as_bytes()) {
                Ok(()) => {},
                Err(e) => { 
                    show_message(s, &format!("Unable to write file: {:?}", e)) ; 
                    return  
                }
            }
        }

        success_message(s, "Export successfull. Press OK to continue.",shared_state.clone(), sndr_ok.clone());
    })
    .button("Cancel", move |s| {                 
        s.pop_layer();
        pwman_quit(s, sndr_cancel.clone(), String::from("")) 
    });
    
    s.add_layer(res);
}