use sha2::{Sha256, Sha512};
use sha1::Sha1;
use hmac::{EagerHash, Hmac, KeyInit, Mac};

pub enum TotpAlgoId {
    Sha1,
    Sha256,
    Sha512
}

pub struct TotpParams {
    pub algo: TotpAlgoId,
    pub secret: Vec<u8>,
    pub period: usize,
    pub digits: usize,
    t0: u64
}

fn calc_hmac<T: EagerHash>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<T>::new_from_slice(key).expect("This should not happen: HMAC key length mismatch");

    hmac.update(data);
    return hmac.finalize().as_bytes().into_iter().cloned().collect();
}

impl TotpParams {
    pub fn new() -> TotpParams {
        return TotpParams { 
            algo: TotpAlgoId::Sha1, 
            secret: vec![0,0,0,0,0,0,0,0,0,0],
            period: 30,
            digits: 6,
            t0: 0
        }
    }

    pub fn get_current_code(&self, unix_time: u64) -> String {
        let mut counter = unix_time - self.t0;
        counter = counter / (self.period as u64);
        let raw = counter.to_be_bytes();

        let data = match &self.algo {
            TotpAlgoId::Sha1 => calc_hmac::<Sha1>(self.secret.as_slice(), raw.as_slice()),
            TotpAlgoId::Sha256 => calc_hmac::<Sha256>(self.secret.as_slice(), raw.as_slice()),
            TotpAlgoId::Sha512 => calc_hmac::<Sha512>(self.secret.as_slice(), raw.as_slice())
        };

        let index = data.last().unwrap() & 0x0F;
        let mut totp_int = (data[index as usize] & 0x7F) as i32;

        for i in index + 1..=index + 3 {
            totp_int = (totp_int * 256) + (data[i as usize] as i32);
        }

        let mod_val = match self.digits {
            6 => 1000000,
            7 => 10000000,
            _ => 100000000,
        };

        return format!("{:0>width$}", totp_int % mod_val, width = self.digits);
    }    

    pub fn get_current_code_formatted(&self, unix_time: u64) -> String {
        return format!("Code: {}", self.get_current_code(unix_time));
    }    
}
