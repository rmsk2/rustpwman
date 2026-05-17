use sha2::{Sha256, Sha512};
use sha1::Sha1;
use hmac::{EagerHash, Hmac, KeyInit, Mac};
use base32;

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

    pub fn from_totp_params(entry_content: String) -> Option<TotpParams> {
        let url_start = entry_content.find("otpauth://")?;
        let tail = &entry_content[url_start..];
        let url_end = tail.find(|c: char| c.is_whitespace()).unwrap_or(tail.len());
        let url = &tail[..url_end];

        if !url.starts_with("otpauth://totp/") {
            return None;
        }

        let query = url.split('?').nth(1)?;

        let mut params = TotpParams::new();
        let mut secret: Option<Vec<u8>> = None;

        for param in query.split('&') {
            let mut parts = param.splitn(2, '=');
            let key = match parts.next() { Some(k) => k, None => continue };
            let value = parts.next().unwrap_or("");

            match key.to_lowercase().as_str() {
                "secret" => {
                    secret = base32::decode(base32::Alphabet::RFC4648 { padding: false }, value);
                }
                "algorithm" => {
                    params.algo = match value.to_uppercase().as_str() {
                        "SHA1"   => TotpAlgoId::Sha1,
                        "SHA256" => TotpAlgoId::Sha256,
                        "SHA512" => TotpAlgoId::Sha512,
                        _ => return None,
                    };
                }
                "digits" => {
                    match value.parse::<usize>() {
                        Ok(d) if d == 6 || d == 7 || d == 8 => { params.digits = d; }
                        Ok(_) => return None,
                        Err(_) => return None
                    }
                }
                "period" => {
                    match value.parse::<usize>() {
                        Ok(p) if p >= 1 && p <= 60 => { params.period = p; }
                        Ok(_) => return None,
                        Err(_) => return None
                    }
                }
                _ => {}
            }
        }

        // secret? propagates None if the "secret" parameter was absent or not valid Base32.
        // Without a decodable secret there is no HMAC key, so TOTP calculation is impossible.
        params.secret = secret?;
        Some(params)
    }
}
