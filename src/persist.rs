use std::fs::File;
use std::fs;
use std::io::BufReader;
use std::io::BufWriter;
//use std::io::{Error, ErrorKind};

pub type PersistCreator = Box<dyn Fn(&String) -> Box<dyn Persister>>;

pub trait Persister {
    fn does_exist(&self) -> std::io::Result<bool>;
    fn persist(&mut self, data: &Vec<u8>) -> std::io::Result<()>;
    fn retrieve(&mut self) -> std::io::Result<Box<Vec<u8>>>;
}

struct FilePersister {
    file_name: String
}

impl FilePersister {
    pub fn new(file_name: &String) -> Box<dyn Persister> {
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
}

pub fn make_file_persist(store_id: &String) -> Box<dyn Persister> {
    return FilePersister::new(store_id);
}
