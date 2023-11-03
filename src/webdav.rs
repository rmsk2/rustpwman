#[cfg(feature = "webdav")]
use crate::persist::Persister;
#[cfg(feature = "webdav")]
use reqwest::{Method, Url, StatusCode};
#[cfg(feature = "webdav")]
use std::io::{Error, ErrorKind};

#[cfg(feature = "webdav")]
pub struct WebDavPersister {
    user_id: String,
    password: String,
    server: String,
    store_id: String
}

#[cfg(feature = "webdav")]
impl WebDavPersister {
    pub fn new(u: &String, p: &String, s: &String, s_id: &String) -> Box<dyn Persister> {
        let res = WebDavPersister {
            user_id: u.clone(),
            password: p.clone(),
            server: s.clone(),
            store_id: s_id.clone()
        };

        return Box::new(res);
    }
}

#[cfg(feature = "webdav")]
impl Persister for WebDavPersister {
    fn does_exist(&self) -> std::io::Result<bool> {
        let body = r#"<?xml version="1.0" encoding="utf-8" ?>
            <D:propfind xmlns:D="DAV:">
                <D:prop><D:getcontentlength/></D:prop>
            </D:propfind>
        "#;

        let url_str = format!("{}{}", &self.server, &self.store_id);
        let url = match Url::parse(&url_str) {
            Ok(u) => u,
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, format!("Not a valid URL: '{}'", &url_str)))
            }
        };

        let response = reqwest::blocking::Client::new()
            .request(Method::from_bytes(b"PROPFIND").unwrap(), url)
            .basic_auth(self.user_id.as_str(), Some(self.password.as_str()))
            .header("depth", "0")
            .body(body)
            .send();

        let status = match response {
            Ok(r) => r.status(),
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, format!("Error: '{}'", e)))
            }
        };

        if status.is_success() {
            return Ok(true)
        }

        if status == StatusCode::NOT_FOUND {
            return Ok(false);
        }

        return Err(Error::new(ErrorKind::Other, format!("HTTP error '{}'", status.as_u16())));
    }

    fn persist(&mut self, data: &Vec<u8>) -> std::io::Result<()> {
        let url_str = format!("{}{}", &self.server, &self.store_id);
        let url = match Url::parse(&url_str) {
            Ok(u) => u,
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, format!("Not a valid URL: '{}'", &url_str)))
            }
        };

        let response = reqwest::blocking::Client::new()
            .request(Method::PUT, url)
            .basic_auth(self.user_id.as_str(), Some(self.password.as_str()))
            .header("content-type", "application/octet-stream")
            .body(data.clone())
            .send();
        
        let status = match response {
            Ok(r) => r.status(),
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, format!("Error: '{}'", e)))
            }
        };

        if !status.is_success() {
            return Err(Error::new(ErrorKind::Other, format!("HTTP error '{}'", status.as_u16())));
        };

        return Ok(());
    }

    fn retrieve(&mut self) -> std::io::Result<Box<Vec<u8>>> {
        let url_str = format!("{}{}", &self.server, &self.store_id);
        let url = match Url::parse(&url_str) {
            Ok(u) => u,
            Err(_) => {
                return Err(Error::new(ErrorKind::Other, format!("Not a valid URL: '{}'", &url_str)))
            }
        };

        let response = reqwest::blocking::Client::new()
            .request(Method::GET, url)
            .basic_auth(self.user_id.as_str(), Some(self.password.as_str()))
            .send();
        
        let resp = match response {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, format!("Error: '{}'", e)))
            }
        };

        if !resp.status().is_success() {
            return Err(Error::new(ErrorKind::Other, format!("HTTP error '{}'", resp.status().as_u16())));
        }

        let res_bytes = match resp.bytes() {
            Ok(b) => b,
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, format!("Error: '{}'", e)))
            },
        };

        let res_data: Vec<u8> = res_bytes.into_iter().collect();

        return Ok(Box::<Vec<u8>>::new(res_data));
    }
}