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

use users;
use std::{path::PathBuf};
use std::io::{Error, ErrorKind};
use crypto::md5::Md5;
use crypto::digest::Digest;
use serde::{Serialize, Deserialize};
use std::fs;
use std::os::unix::net::UnixStream;


#[derive(Serialize, Deserialize, Debug)]
pub struct PWRequest {
    #[serde(rename(deserialize = "Command"))]
    #[serde(rename(serialize = "Command"))]
    command: String,    
    #[serde(rename(deserialize = "PwName"))]
    #[serde(rename(serialize = "PwName"))]
    pw_name: String,
    #[serde(rename(deserialize = "PwData"))]
    #[serde(rename(serialize = "PwData"))]
    pw_data: String
}

impl PWRequest {
    pub fn new_get_request(pw_name: &String) -> PWRequest {
        return PWRequest {
            command: String::from("GET"),
            pw_name: pw_name.clone(),
            pw_data: String::from("")
        }
    }

    pub fn new_reset_request(pw_name: &String) -> PWRequest {
        return PWRequest {
            command: String::from("RST"),
            pw_name: pw_name.clone(),
            pw_data: String::from("")
        }
    }
    
    pub fn new_set_pw_request(pw_name: &String, password: &String) -> PWRequest {
        return PWRequest {
            command: String::from("SET"),
            pw_name: pw_name.clone(),
            pw_data: password.clone()
        }
    }    

    pub fn send(self: &Self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        let uds_request_text = serde_json::to_string(self)?;
        let uds_request_bytes = uds_request_text.as_bytes();

        if uds_request_bytes.len() > 65535 {
            return Err(Error::new(ErrorKind::Other, "PWMAN Request data is too large"));
        }

        let len = uds_request_bytes.len();
        let len_buffer = [(len / 256) as u8, (len % 256) as u8];
        w.write_all(&len_buffer)?;
        w.write_all(uds_request_bytes)?;

        return Ok(());
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct PWResponse {
    #[serde(rename(deserialize = "ResultCode"))]
    #[serde(rename(serialize = "ResultCode"))]
    result_code: u32,    
    #[serde(rename(deserialize = "ResultData"))]
    #[serde(rename(serialize = "ResultData"))]
    result_data: String,
}

impl PWResponse {
    pub fn receive(r: &mut dyn std::io::Read) -> std::io::Result<PWResponse> {
        let mut pw_response_len: [u8; 2] = [0, 0];
        r.read_exact(&mut pw_response_len)?;
        let response_len : usize = (pw_response_len[0] as usize) * 256 + (pw_response_len[1]) as usize;
        let mut pw_response: Vec<u8> = vec![0; response_len];
        r.read_exact(&mut pw_response)?;
    
    
        let s = match std::str::from_utf8(&pw_response) {
            Ok(s) => s,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Response not UTF-8"))
        };
    
        let response : PWResponse = serde_json::from_str(s)?;

        return Ok(response);
    }
}

pub trait ReaderWriter: std::io::Read + std::io::Write {}
impl<T> ReaderWriter for T where T: std::io::Read + std::io::Write {}

fn hex_string(buf: &[u8]) -> String {
    let mut result = String::from("");
    
    for i in buf {
        result.push_str(format!("{:02x}", i).as_str());
    }
    
    return result;
}

fn hash_password_file_name(password_file: &String) -> std::io::Result<String> {
    let pw_file = PathBuf::from(password_file);
    let abs_file = fs::canonicalize(pw_file)?;
    let path_as_string = match abs_file.to_str() {
        Some(s) => String::from(s),
        None => return Err(Error::new(ErrorKind::Other, "File path not UTF-8"))
    };

    let mut res_buffer: [u8; 16] = [0; 16];
    let mut md5 = Md5::new();

    md5.input_str(&path_as_string);
    md5.result(&mut res_buffer);
    let name: String = format!("PWMAN:{}", hex_string(&res_buffer));

    println!("{}", name);

    return Ok(name);
}

pub trait PWManClient {
    fn connect(self: &Self) -> std::io::Result<Box<dyn ReaderWriter>>;
    fn get_pw_file_id(self: &Self) -> &String;

    fn transact(self: &Self, request: &PWRequest) -> std::io::Result<String>  {
        let mut stream = self.connect()?;

        request.send(&mut stream)?;    
        let response = PWResponse::receive(&mut stream)?;
    
        if response.result_code != 0 {
            return Err(Error::new(ErrorKind::Other, format!("Server returned error code: {}", response.result_code)));
        }
    
        return Ok(response.result_data);
    }

    fn get_password(self: &Self) -> std::io::Result<String> {
        let request = PWRequest::new_get_request(self.get_pw_file_id());
        return self.transact(&request)
    }    

    fn reset_password(self: &Self) -> std::io::Result<()> {
        let request = PWRequest::new_reset_request(self.get_pw_file_id());
        return match self.transact(&request) {
            Err(e) => Err(e),
            Ok(_) => Ok(())
        }
    }    
    
    fn set_password(self: &Self, password: &String) -> std::io::Result<()> {
        let request = PWRequest::new_set_pw_request(self.get_pw_file_id(), password);
        return match self.transact(&request) {
            Err(e) => Err(e),
            Ok(_) => Ok(())
        }
    }    
}

pub struct UDSClient {
    socket_file: PathBuf,
    password_file_id: String
}

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