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

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use crate::fcrypt;
use crate::persist::Persister;
use crate::undo::UndoRepo;
use fcrypt::KeyDeriver;


#[derive(Serialize, Deserialize, Debug)]
pub struct KvEntry {
    #[serde(rename(deserialize = "Key"))]
    #[serde(rename(serialize = "Key"))]    
    pub key: String,
    #[serde(rename(deserialize = "Text"))]
    #[serde(rename(serialize = "Text"))]    
    pub value: String 
}

impl KvEntry {
    pub fn new(k: &String, v: &String) -> KvEntry {
        return KvEntry {
            key: k.clone(),
            value: v.clone()
        }
    }
}

pub struct JotsIter<'a> {
    all_keys: Vec<&'a String>,
    current_pos: usize,
}

impl<'a> JotsIter<'a> {
    fn new(j: &'a Jots) -> JotsIter {
        let mut temp: Vec<&String> = (&j.contents).into_iter().map(|i| i.0).collect();
        temp.sort();
        
        return JotsIter {
            all_keys: temp,
            current_pos: 0,
        };
    }
}

impl<'a> Iterator for JotsIter<'a> {
    type Item=&'a String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_pos < self.all_keys.len() {
            let temp = Some(self.all_keys[self.current_pos]);
            self.current_pos += 1;
            return temp;
        } else {
            return None;
        }
    }
}

pub struct Jots {
    pub contents: HashMap<String, String>,
    pub kdf: KeyDeriver,
    pub kdf_id: fcrypt::KdfId,
    pub dirty: bool,
    pub undoer: UndoRepo<String, String>
}

impl Jots {
    pub fn new(d: KeyDeriver, kdf_id: fcrypt::KdfId) -> Jots {
        return Jots {
            contents: HashMap::new(),
            kdf: d,
            kdf_id: kdf_id,
            dirty: false,
            undoer: UndoRepo::<String, String>::new()
        };
    }

    pub fn new_id(d: KeyDeriver, kdf_id: fcrypt::KdfId) -> Jots {
        return Jots::new(d, kdf_id);
    }

    pub fn is_dirty(&self) -> bool {
        return self.dirty;
    }

    pub fn mark_as_clean(&mut self) {
        self.dirty = false;
        self.undoer.clear();
    }

    pub fn len(&self) -> usize {
        return self.contents.len();
    }

    pub fn from_reader<T: Read>(&mut self, r: T) -> std::io::Result<()> {
        let reader = BufReader::new(r);
        let raw_struct: Vec<KvEntry> = serde_json::from_reader(reader)?;

        self.contents.clear();
    
        for i in raw_struct {
            self.contents.insert(i.key, i.value);
        }

        return Ok(());
    }

    pub fn to_writer<T: Write>(&self, w: T) -> std::io::Result<()> {
        let mut raw_data: Vec<KvEntry> = Vec::new();
        let writer = BufWriter::new(w);

        for i in &self.contents {
            raw_data.push(KvEntry::new(i.0, i.1));
        }

        serde_json::to_writer_pretty(writer, &raw_data)?;

        return Ok(());
    }

    pub fn print(&self) {
        (&self.contents).iter().for_each(|i| {println!("{}: {}", i.0, i.1);} );
    }    

    fn insert_int(&mut self, k: &String, v: &String) {
        self.contents.insert(k.clone(), v.clone());
        self.dirty = true;
    }

    fn remove_int(&mut self, k: &String) {
        let _ = self.contents.remove(k);
        self.dirty = true;
    }

    pub fn modify(&mut self, k: &String, v: &String) {
        let old_value = match self.get(k) {
            Some(o) => o,
            None => return
        };

        self.insert_int(k, v);

        let msg = format!("Modify entry '{}'", k);
        let old_key = k.clone();

        self.undoer.push(&msg, Box::new(move |s: &mut HashMap<String, String>| -> bool {
            s.insert(old_key.clone(), old_value.clone());
    
            return true;
        }));
    }

    pub fn delete(&mut self, k: &String) {
        let old_value = match self.get(k) {
            Some(o) => o,
            None => return
        };

        self.remove_int(k);

        let msg = format!("Delete entry '{}'", k);
        let old_key = k.clone();

        self.undoer.push(&msg, Box::new(move |s: &mut HashMap<String, String>| -> bool {
            s.insert(old_key.clone(), old_value.clone());
    
            return true;
        }));
    }

    pub fn get(&self, k: &String) -> Option<String> {
        let v = match self.contents.get(k) {
            None => { return None },
            Some(val) => val
        };

        return Some(v.clone());
    }  

    // false means add has failed
    pub fn add(&mut self, k: &String, v: &String) -> bool {
        // Check for entry with the given name. It must not exist.
        let res = match self.get(k) {
            None => {
                self.insert_int(k, v);
                true
            },
            _ => return false // Entry already exists
        };

        let msg = format!("Add entry '{}'", k);
        let old_key = k.clone();

        self.undoer.push(&msg, Box::new(move |s: &mut HashMap<String, String>| -> bool {
            s.remove(&old_key);
    
            return true;
        }));

        return res;
    }

    pub fn entry_exists(&self, k: &String) -> bool {
        match self.get(k) {
            None => false,
            Some(_) => true,
        }
    }

    pub fn undo(&mut self) -> (String, bool) {
        let res = self.undoer.undo_one(&mut self.contents);

        if res.1 {
            self.dirty = !self.undoer.is_all_undone();
        }

        return res;
    }

    // false means rename has failed
    pub fn rename(&mut self, k_old: &String, k_new: &String) -> bool {
        // Check if entry k_old exists. It has to exist.
        let contents = match self.get(k_old) {
            None => { return false; },
            Some(c) => c,
        };

        // Check if entry k_new exists. It must not exist.
        let res = match self.get(k_new) {
            None => {
                self.remove_int(k_old);
                self.insert_int(k_new, &contents);
                true
            },
            _ => return false
        };

        let msg = format!("Rename entry '{}' to '{}'", k_old, k_new);
        let old_key = k_old.clone();
        let new_key = k_new.clone();

        self.undoer.push(&msg, Box::new(move |s: &mut HashMap<String, String>| -> bool {
            s.remove(&new_key);
            s.insert(old_key.clone(), contents.clone());
    
            return true;
        }));  

        return res;      
    }

    pub fn from_enc_file(&mut self, file_name: &str, password: &str) -> std::io::Result<()> {
        let mut ctx = fcrypt::GcmContext::new_with_kdf(self.kdf, self.kdf_id);

        let data = ctx.from_file(file_name)?;
        let plain_data = match ctx.decrypt(password, &data) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        self.from_reader(plain_data.as_slice())?;
        self.mark_as_clean();

        return Ok(());
    }

    pub fn retrieve(&mut self, p: &mut Box<dyn Persister>, password: &str) -> std::io::Result<()> {
        let mut ctx = fcrypt::GcmContext::new_with_kdf(self.kdf, self.kdf_id);

        let data = ctx.retrieve(p)?;
        let plain_data = match ctx.decrypt(password, &data) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        self.from_reader(plain_data.as_slice())?;
        self.mark_as_clean();

        return Ok(());
    }

    pub fn to_enc_file(&mut self, file_name: &str, password: &str) -> std::io::Result<()> {
        let mut ctx = fcrypt::GcmContext::new_with_kdf(self.kdf, self.kdf_id);
        let mut serialized: Vec<u8> = Vec::new();

        self.to_writer(&mut serialized)?;
        let enc_data = match ctx.encrypt(password, &serialized) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        ctx.to_file(&enc_data, file_name)?;
        self.mark_as_clean();

        return Ok(());
    }

    pub fn persist(&mut self, p: &mut Box<dyn Persister>, password: &str) -> std::io::Result<()> {
        let mut ctx = fcrypt::GcmContext::new_with_kdf(self.kdf, self.kdf_id);
        let mut serialized: Vec<u8> = Vec::new();

        self.to_writer(&mut serialized)?;
        let enc_data = match ctx.encrypt(password, &serialized) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        ctx.persist(&enc_data, p)?;
        self.mark_as_clean();

        return Ok(());
    }    
}

impl<'a> IntoIterator for &'a Jots {
    type Item = &'a String;
    type IntoIter = JotsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        return JotsIter::new(&self);
    }
}