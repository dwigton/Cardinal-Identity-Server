use database::schema::write_grant_scope;
use database::MyConnection;
use diesel::prelude::*;
use chrono::NaiveDateTime;
use model::Signable;
use error::CommonResult;
use encryption::secure_hash;


pub struct UnlockedWriteScope {
    pub id: i32,
    pub application_id: i32,
    pub code: String,
    pub display_name: String,
    pub description: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
}

pub struct NewWriteScope {
    pub application_id: i32,
    pub code: String,
    pub display_name: String,
    pub description: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
}

#[derive(PartialEq, Debug, Queryable)]
pub struct LockedWriteScope {
    pub id: i32,
    pub application_id: i32,
    pub code: String,
    pub display_name: String,
    pub description: String,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
}

impl Signable for NewWriteScope {
    fn record_hash(&self) -> [u8; 32] {
       secure_hash(&[
                   self.application_code.as_bytes(),
                   self.code.as_bytes(), 
                   &self.public_key,
                   &self.expiration_date.timestamp().to_le_bytes(),
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl Signable for LockedWriteScope {
    fn record_hash(&self) -> [u8; 32] {
       secure_hash(&[
                   self.application_code.as_bytes(),
                   self.code.as_bytes(), 
                   &self.public_key,
                   &self.expiration_date.timestamp().to_le_bytes(),
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl NewWriteScope {
    pub fn save(self, connection: &MyConnection) -> CommonResult<LockedWriteScope> {
        Ok(diesel::insert_into(write_grant_scope::table).values(self).get_result(connection)?)
    }
}
