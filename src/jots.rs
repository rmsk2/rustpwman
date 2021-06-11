use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KvEntry {
    #[serde(rename(deserialize = "Key"))]
    #[serde(rename(serialize = "Key"))]    
    key: String,
    #[serde(rename(deserialize = "Text"))]
    #[serde(rename(serialize = "Text"))]    
    value: String 
}


impl KvEntry {
    pub fn new(k: String, v: String) -> KvEntry {
        return KvEntry {
            key: k,
            value: v
        }
    }
}