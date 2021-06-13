use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::{Error, ErrorKind};
use crate::fcrypt;

#[derive(Serialize, Deserialize, Debug)]
pub struct KvEntry {
    #[serde(rename(deserialize = "Key"))]
    #[serde(rename(serialize = "Key"))]    
    pub key: String,
    #[serde(rename(deserialize = "Text"))]
    #[serde(rename(serialize = "Text"))]    
    pub value: String 
}

pub trait JotsStore {
    fn from_enc_file(&mut self, file_name: &str, password: &str) -> std::io::Result<()>;
    fn to_enc_file(&self, file_name: &str, password: &str) -> std::io::Result<()>;
    fn insert(&mut self, k: &String, v: &String);
    fn remove(&mut self, k: &String);
    fn get(&self, k: &String) -> Option<String>;
}

impl KvEntry {
    pub fn new(k: &String, v: &String) -> KvEntry {
        return KvEntry {
            key: k.clone(),
            value: v.clone()
        }
    }
}

pub struct Jots {
    pub contents: HashMap<String, String>
}

impl Jots {
    pub fn new() -> Jots {
        return Jots {
            contents: HashMap::new()
        };
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
}

impl JotsStore for Jots {
    fn insert(&mut self, k: &String, v: &String) {
        self.contents.insert(k.clone(), v.clone());
    }
    
    fn remove(&mut self, k: &String) {
        let _ = self.contents.remove(k);
    }

    fn get(&self, k: &String) -> Option<String> {
        let res = match self.contents.get(k) {
            None => {return None },
            Some(s) => s
        };

        return Some(res.clone());
    }

    fn from_enc_file(&mut self, file_name: &str, password: &str) -> std::io::Result<()> {
        let mut ctx = fcrypt::GcmContext::new();

        let data = ctx.from_file(file_name)?;
        let plain_data = match ctx.decrypt(password, &data) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        self.from_reader(plain_data.as_slice())?;

        return Ok(());
    }

    fn to_enc_file(&self, file_name: &str, password: &str) -> std::io::Result<()> {
        let mut ctx = fcrypt::GcmContext::new();
        let mut serialized: Vec<u8> = Vec::new();

        self.to_writer(&mut serialized)?;
        let enc_data = match ctx.encrypt(password, &serialized) {
            Err(e) => { return Err(Error::new(ErrorKind::Other, format!("{:?}", e))); },
            Ok(d) => d
        };

        ctx.to_file(&enc_data, file_name)?;

        return Ok(());
    }
}
