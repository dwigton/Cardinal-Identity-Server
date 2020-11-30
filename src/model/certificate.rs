use model::Scope;
use chrono::NaiveDateTime;
use encryption::{lpad_to_256, hash_by_parts};

#[derive(Clone)]
pub struct CertData {
    pub signing_key:     [u8; 32],
    pub public_key:      [u8; 32],
    pub scope:           Scope,
    pub expiration_date: NaiveDateTime,
}

impl CertData {
    pub fn hash(&self) -> [u8; 32] {
        let time = self.expiration_date.timestamp().to_le_bytes();
        let date = lpad_to_256(&time);

        hash_by_parts(&[
                      &self.signing_key,
                      &self.public_key,
                      &self.scope.hash(),
                      &date,
        ])
    }
}

pub struct Certificate {
    pub data: CertData,
    pub signature: [u8; 64],
}

impl Certificate {
    pub fn to_bytes(&self) -> [u8; 160] {
        let mut bytes = [0u8; 160];
        
        for i in 0..32 {
            bytes[i] = self.data.signing_key[i];
            bytes[i + 32] = self.data.public_key[i];
            bytes[i + 64] = self.data.scope.hash()[i];
            bytes[i + 128] = self.signature[i];
        }

        for i in 0..8 {
            bytes[i + 96] = self.data.expiration_date.timestamp().to_le_bytes()[i];
        }

        bytes
    }

    pub fn signature(&self) -> Vec<u8> {
        self.signature.to_vec()
    }
}
