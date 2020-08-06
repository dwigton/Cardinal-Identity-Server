use chrono::NaiveDateTime;

pub struct WriteScope {
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
                   self.code.as_bytes(), 
                   self.description.as_bytes(),
                   self.server_url.as_bytes()
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

