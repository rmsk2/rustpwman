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
use crate::persist::SendSyncPersister;
use crate::undo::UndoRepo;
use crate::obfuscate::Cfb8;
use fcrypt::KeyDeriver;
use fcrypt::KdfId;
use fcrypt::Cryptor;
use rand::Rng;
use sha2::{Sha256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};


pub type CryptorGen = Box<dyn Fn(KeyDeriver, KdfId) -> Box<dyn Cryptor>  + Send + Sync>;
pub type BackupCallback = Box<dyn Fn(&Vec<u8>) -> std::io::Result<()> + Send + Sync> ;

struct MapObfuscator {
    session_key: Vec<u8>
}

// Use this to perform obfuscation of sensitive values in memory. This is more of a hygiene feature
// than a security feature because the sensitive values will be in plaintext in memory as soon as
// they are displayed or copied or during en-/decryption of the whole password file. On top of that
// anyone who can inspect the memory of a running process can create a key logger to steal the master
// password and/or is root anyway .... . Additionally the obfuscation key is in plaintext in RAM.
impl MapObfuscator {
    fn new() -> MapObfuscator {
        let mut key = vec![0u8; 16];
        rand::rng().fill_bytes(&mut key);

        return MapObfuscator { session_key: key.clone() };
    }

    fn derive_iv(map_key: &str) -> Vec<u8> {
        let mut sha = Sha256::new();
        sha.update(map_key.as_bytes());
        return sha.finalize().into_iter().take(16).collect();
    }

    fn encrypt_for_memory(&self, value: &str, map_key: &str) -> Vec<u8> {
        let mut data = value.as_bytes().to_vec();
        Cfb8::new_aes_128_cfb((&self.session_key).to_vec(), MapObfuscator::derive_iv(map_key)).encrypt(&mut data);
        return data;
    }

    fn decrypt_from_memory(&self, ciphertext: &[u8], map_key: &str) -> String {
        let mut data = ciphertext.to_vec();
        Cfb8::new_aes_128_cfb((&self.session_key).to_vec(), MapObfuscator::derive_iv(map_key)).decrypt(&mut data);
        return String::from_utf8(data).expect("decrypted value is not valid UTF-8");
    }
}


#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
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
    fn new(j: &Jots) -> JotsIter<'_> {
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
    contents: HashMap<String, Vec<u8>>,
    obf: MapObfuscator,
    kdf: KeyDeriver,
    kdf_id: fcrypt::KdfId,
    dirty: bool,
    pub undoer: UndoRepo<String, Vec<u8>>,
    pub cr_gen: CryptorGen,
    pub backup_cb: Option<BackupCallback>
}


impl Jots {
    pub fn new(d: KeyDeriver, kdf_id: fcrypt::KdfId, g: CryptorGen) -> Jots {
        return Jots {
            contents: HashMap::new(),
            obf: MapObfuscator::new(),
            kdf: d,
            kdf_id: kdf_id,
            dirty: false,
            undoer: UndoRepo::<String, Vec<u8>>::new(),
            cr_gen: g,
            backup_cb: None
        };
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
            let enc = self.obf.encrypt_for_memory(&i.value, &i.key);
            self.contents.insert(i.key.clone(), enc);
        }

        return Ok(());
    }

    pub fn to_writer<T: Write>(&self, w: T) -> std::io::Result<()> {
        let mut raw_data: Vec<KvEntry> = Vec::new();
        let writer = BufWriter::new(w);

        for i in &self.contents {
            let mut plaintext = self.obf.decrypt_from_memory(i.1, i.0);
            raw_data.push(KvEntry::new(i.0, &plaintext));
            plaintext.zeroize();
        }

        serde_json::to_writer_pretty(writer, &raw_data)?;

        return Ok(());
    }

    pub fn print(&self) {
        (&self.contents).iter().for_each(|i| {
            let mut plaintext = self.obf.decrypt_from_memory(i.1, i.0);
            println!("{}: {}", i.0, plaintext);
            plaintext.zeroize();
        });
    }

    fn insert_int(&mut self, k: &String, v: &String) {
        self.contents.insert(k.clone(), self.obf.encrypt_for_memory(v, k));
        self.dirty = true;
    }

    fn remove_int(&mut self, k: &String) {
        let _ = self.contents.remove(k);
        self.dirty = true;
    }

    pub fn modify(&mut self, k: &String, v: &String) {
        if self.get(k).is_none() {
            return;
        }

        let old_encrypted = self.contents.get(k).cloned().unwrap();
        self.insert_int(k, v);

        let msg = format!("Modify entry '{}'", k);
        let old_key = k.clone();

        self.undoer.push(&msg, Box::new(move |s: &mut HashMap<String, Vec<u8>>| -> bool {
            s.insert(old_key.clone(), old_encrypted.clone());

            return true;
        }));
    }

    pub fn delete(&mut self, k: &String) {
        let old_encrypted = match self.contents.get(k).cloned() {
            Some(v) => v,
            None => return
        };

        self.remove_int(k);

        let msg = format!("Delete entry '{}'", k);
        let old_key = k.clone();

        self.undoer.push(&msg, Box::new(move |s: &mut HashMap<String, Vec<u8>>| -> bool {
            s.insert(old_key.clone(), old_encrypted.clone());

            return true;
        }));
    }

    pub fn get(&self, k: &String) -> Option<String> {
        let v = match self.contents.get(k) {
            None => { return None },
            Some(val) => val
        };

        return Some(self.obf.decrypt_from_memory(v, k));
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

        self.undoer.push(&msg, Box::new(move |s: &mut HashMap<String, Vec<u8>>| -> bool {
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
        let old_encrypted = match self.contents.get(k_old).cloned() {
            None => { return false; },
            Some(c) => c,
        };

        // Check if entry k_new exists. It must not exist.
        let res = match self.get(k_new) {
            None => {
                let mut decrypted = self.obf.decrypt_from_memory(&old_encrypted, k_old);
                self.remove_int(k_old);
                self.insert_int(k_new, &decrypted);
                decrypted.zeroize();
                true
            },
            _ => return false
        };

        let msg = format!("Rename entry '{}' to '{}'", k_old, k_new);
        let old_key = k_old.clone();
        let new_key = k_new.clone();

        self.undoer.push(&msg, Box::new(move |s: &mut HashMap<String, Vec<u8>>| -> bool {
            s.remove(&new_key);
            s.insert(old_key.clone(), old_encrypted.clone());

            return true;
        }));

        return res;
    }

    pub fn from_enc_file(&mut self, file_name: &str, password: &str) -> std::io::Result<()> {
        let mut ctx = (self.cr_gen)(self.kdf, self.kdf_id);

        let data = ctx.from_file(file_name)?;
        let mut plain_data = match ctx.decrypt(password, &data) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        self.from_reader(plain_data.as_slice())?;
        self.mark_as_clean();
        plain_data.zeroize();

        return Ok(());
    }

    pub fn retrieve(&mut self, p: &mut SendSyncPersister, password: &str) -> std::io::Result<()> {
        let mut ctx = (self.cr_gen)(self.kdf, self.kdf_id);

        let (data, raw_data) = ctx.retrieve(p)?;

        if let Some(cb) = &self.backup_cb {
            // ignore result
            _ = cb(&raw_data);
        }

        let mut plain_data = match ctx.decrypt(password, &data) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        self.from_reader(plain_data.as_slice())?;
        self.mark_as_clean();
        plain_data.zeroize();

        return Ok(());
    }

    pub fn to_enc_file(&mut self, file_name: &str, password: &str) -> std::io::Result<()> {
        let mut ctx = (self.cr_gen)(self.kdf, self.kdf_id);
        let mut serialized: Vec<u8> = Vec::new();

        self.to_writer(&mut serialized)?;
        let enc_data = match ctx.encrypt(password, &serialized) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        ctx.to_file(&enc_data, file_name)?;
        self.mark_as_clean();
        serialized.zeroize();

        return Ok(());
    }

    pub fn persist(&mut self, p: &mut SendSyncPersister, password: &str) -> std::io::Result<()> {
        let mut ctx = (self.cr_gen)(self.kdf, self.kdf_id);
        let mut serialized: Vec<u8> = Vec::new();

        self.to_writer(&mut serialized)?;
        let enc_data = match ctx.encrypt(password, &serialized) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        ctx.persist(&enc_data, p)?;
        self.mark_as_clean();
        serialized.zeroize();

        return Ok(());
    }

    pub fn search(&self, search_term: &String) -> Vec<String> {
        let mut res = vec![];
        let search_lower = search_term.to_lowercase();

        let search_res: Vec<&String> = self.into_iter().filter(|&x| x.to_lowercase().contains(&search_lower)).collect();

        if search_res.len() != 0 {
            for i in search_res {
                let h = String::from(i.as_str());
                res.push(h);
            }
        }

        return res;
    }
}

impl<'a> IntoIterator for &'a Jots {
    type Item = &'a String;
    type IntoIter = JotsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        return JotsIter::new(&self);
    }
}