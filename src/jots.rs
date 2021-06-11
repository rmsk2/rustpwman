use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::io::Read;
use std::io::Write;
//use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;

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
        for i in &self.contents {
            println!("{}: {}", i.0, i.1);
        }
    }
}
