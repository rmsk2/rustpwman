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

use std::string::String;
use std::process::{Command, Stdio};
use std::io::Write;
use std::str;

pub fn get_clipboard(cmd: &str) -> Option<String> {
    if cmd.len() == 0 {
        return None;
    }

    let cmd_args = cmd.split_ascii_whitespace();
    let collection: Vec<&str> = cmd_args.collect(); 

    if collection.len() < 1 {
        return None;
    }   

    let output_res = Command::new(collection[0])
                        .args(collection[1..].into_iter())
                        .output();
    
    let output = match output_res {
        Ok(d) => d,
        Err(_) => {return None;}
    };

    if !output.status.success() {
        return None;
    }

    let s = match str::from_utf8(output.stdout.as_slice()) {
        Ok(v) => v,
        Err(_) => {return None},
    };

    return Some(String::from(s));
}

// Return value false means that no error occurred
pub fn set_clipboard(cmd: String, data: Box<String>) -> bool {
    let cmd_args = cmd.split_ascii_whitespace();
    let collection: Vec<&str> = cmd_args.collect(); 

    let mut child = match Command::new(collection[0])
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .stdout(Stdio::null())
        .args(collection[1..].into_iter())
        .spawn()
        {
            Ok(v) => v,
            Err(_) => { return true; }
        };

    let mut stdin = match child.stdin.take() {
        Some(v) => v,
        None => { return true; }
    };
    
   std::thread::spawn(move || {
        stdin.write_all(data.as_bytes()).expect("failed to talk to child preocess")
    });

    match child.wait() {
        Ok(status) => {
            return !status.success();
        },
        Err(_) => { return true; }
    };
}