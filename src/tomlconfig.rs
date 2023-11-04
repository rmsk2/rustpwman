
use std::io::{Error, ErrorKind};
use serde::{Serialize, Deserialize};
use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;

#[derive(Serialize, Deserialize, Debug)]
pub struct RustPwManSerialize {
    pub seclevel: usize,
    pub pbkdf: String,
    pub pwgen: String,
    pub clip_cmd: String,
    pub copy_cmd: String,
    pub webdav_user: String,
    pub webdav_pw: String,
    pub webdav_server: String,
}

impl RustPwManSerialize {
    pub fn new(seclevel: usize, pbkdf: &str, pwgen: &str, clip_command: &str, copy_command: &str, user: &str, pw: &str, server: &str) -> Self {
        return RustPwManSerialize {
            seclevel: seclevel,
            pbkdf: String::from(pbkdf),
            pwgen: String::from(pwgen),
            clip_cmd: String::from(clip_command),
            copy_cmd: String::from(copy_command),
            webdav_user: String::from(user),
            webdav_pw: String::from(pw),
            webdav_server: String::from(server),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    defaults: RustPwManSerialize
}

pub fn load(file_path: &std::path::PathBuf, file_was_read: &mut bool) -> std::io::Result<RustPwManSerialize> {
    *file_was_read = false;
    let raw_string: String = match fs::read_to_string(file_path)
    {
        Ok(d) => d,
        Err(e) => return Err(e) 
    };

    *file_was_read = true;

    let value: Config = match toml::from_str(&raw_string[..]) {
        Ok(v) => v,
        Err(e) => return Err(Error::new(ErrorKind::Other, format!("{:?}", e)))
    };

    return Ok(value.defaults);
}

pub fn save(file_path: &std::path::PathBuf, config: RustPwManSerialize) -> Option<Error> {
    let c = Config {
        defaults: config,
    };

    let toml_str = match toml::to_string(&c) {
        Ok(s) => s,
        Err(e) => return Some(Error::new(ErrorKind::Other, format!("{:?}", e)))
    };

    let file = match File::create(file_path) {
        Ok(f) => f,
        Err(e) => return Some(e)
    };

    let mut w = BufWriter::new(file);

    match w.write_all(toml_str.as_bytes()) {
        Ok(_) => (),
        Err(e) => return Some(e)
    };

    return None;
} 