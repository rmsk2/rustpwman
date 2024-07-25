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


use std::fs::File;
use std::fs;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

pub type PersistCreator = Box<dyn Fn(&String) -> SendSyncPersister + Send + Sync>;
pub type SendSyncPersister = Box<dyn Persister + Send + Sync>;

pub trait Persister {
    fn does_exist(&self) -> std::io::Result<bool>;
    fn persist(&mut self, data: &Vec<u8>) -> std::io::Result<()>;
    fn retrieve(&mut self) -> std::io::Result<Box<Vec<u8>>>;
    fn get_canonical_path(&self) -> std::io::Result<String>;
    fn get_type(&self) -> String;
}

pub struct FilePersister {
    file_name: String
}

impl FilePersister {
    pub fn new(file_name: &String) -> SendSyncPersister {
        let res = FilePersister {
            file_name: file_name.clone(),
        };

        return Box::new(res);
    }
}

impl Persister for FilePersister {
    fn does_exist(&self) -> std::io::Result<bool> {
        return Ok(fs::metadata(self.file_name.as_str()).is_ok());
        //return Err(Error::new(ErrorKind::Other, "Connection failed"));
    }

    fn persist(&mut self, data: &Vec<u8>) -> std::io::Result<()> {
        let file = File::create(&self.file_name)?;
        let mut w = BufWriter::new(file);

        std::io::copy(&mut data.as_slice(), &mut w).unwrap();

        return Ok(());
    }

    fn retrieve(&mut self) -> std::io::Result<Box<Vec<u8>>> {
        let file = File::open(&self.file_name)?;
        let mut reader = BufReader::new(file);
        let mut data: Vec<u8> = vec![];

        std::io::copy(&mut reader, &mut data).unwrap();

        return Ok(Box::<Vec<u8>>::new(data));
    }

    fn get_canonical_path(&self) -> std::io::Result<String> {
        let pw_file = PathBuf::from(&self.file_name);
        let abs_file = fs::canonicalize(pw_file)?;
        let path_as_string = match abs_file.to_str() {
            Some(s) => String::from(s),
            None => return Err(Error::new(ErrorKind::Other, "File path not UTF-8"))
        };

        return Ok(path_as_string);
    }

    fn get_type(&self) -> String {
        return String::from("Filesystem")
    }
}

