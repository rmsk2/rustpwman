/* Copyright 2022 Martin Grap

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#![allow(dead_code)]

use std::{path::PathBuf};
use std::io::{Error, ErrorKind};
use std::os::unix::net::UnixStream;

use crate::pwman_client::PWManClient;
use crate::pwman_client::ReaderWriter;
use crate::pwman_client::hash_password_file_name;

#[cfg(feature = "pwmanclientux")]
pub struct UDSClient {
    socket_file: PathBuf,
    password_file_id: String
}

#[cfg(feature = "pwmanclientux")]
impl UDSClient {
    fn calc_socket_name() -> std::io::Result<PathBuf> {
        let mut p = PathBuf::from("/tmp");
    
        let user_name = match users::get_current_username() {
            Some(u) => u,
            None => return Err(Error::new(ErrorKind::Other, "Unable to determine user name"))
        };
    
        p.push(user_name);
        p.set_extension("pwman");
    
        return Ok(p);
    }    

    pub fn new(pwman_file_name: String) -> std::io::Result<UDSClient> {
        let p = UDSClient::calc_socket_name()?;
        let pw_hash_name = hash_password_file_name(&pwman_file_name)?;

        let res = UDSClient { 
            socket_file: p, 
            password_file_id: pw_hash_name 
        };

        return Ok(res);
    }  
}

#[cfg(feature = "pwmanclientux")]
impl PWManClient for UDSClient {
    fn connect(self :&Self) -> std::io::Result<Box<dyn ReaderWriter>> {
        let s = match UnixStream::connect(&self.socket_file) {
            Err(e) => return Err(e),
            Ok(s) => s
        };

        return Ok(Box::new(s));
    }

    fn get_pw_file_id(self: &Self) -> &String {
        return &self.password_file_id;
    }
}