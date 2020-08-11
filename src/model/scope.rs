use database::schema::write_grant_scope;
use database::schema::read_grant_scope;
use database::MyConnection;
use diesel::prelude::*;
use diesel::expression::dsl::any;
use chrono::NaiveDateTime;
use chrono::{Duration, Utc};
use model::Signable;
use model::account::UnlockedAccount;
use model::application::Application;
use error::CommonResult;
use encryption::{secure_hash, random_int_256};
use encryption::signing_key::SigningKey;

pub struct WriteScope {}

pub struct UnlockedWriteScope {
    pub id: i32,
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "write_grant_scope"]
pub struct NewWriteScope {
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
}

#[derive(PartialEq, Debug, Queryable, Identifiable)]
#[table_name = "write_grant_scope"]
pub struct LockedWriteScope {
    pub id: i32,
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
}

impl WriteScope {
    pub fn new(code: &str, application: &Application, account: &UnlockedAccount) -> NewWriteScope{
        let salt = random_int_256();
        
        // expire in one year as default
        let expiration_date       = (Utc::now() + Duration::days(365)).naive_utc();
        let signing_key           = SigningKey::new();
        let encryption_key        = account.generate_key(&salt);
        let encrypted_private_key = signing_key.encrypted_private_key(&encryption_key).to_vec();
        let public_key            = signing_key.public_key().to_vec();

        let mut scope = NewWriteScope {
            application_id:        application.id,
            application_code:      application.code.clone(),
            code:                  code.to_owned(),
            display_name:          None,
            description:           None,
            public_key,
            encrypted_private_key,
            private_key_salt: salt.to_vec(),
            expiration_date,
            signature: Vec::new(),
        };

        scope.signature = account.sign_record(&scope);

        scope
    }

    pub fn load_codes(codes: Vec<String>, application: &Application, connection: &MyConnection) -> CommonResult<Vec<LockedWriteScope>> {
        Ok(
            write_grant_scope::table
            .filter( write_grant_scope::application_id.eq(application.id))
            .filter( write_grant_scope::code.eq(any(codes)))
            .get_results(connection)?
            )
    }
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

impl LockedWriteScope {

    pub fn delete(&mut self, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(write_grant_scope::table.filter(write_grant_scope::id.eq(self.id))).execute(connection)?;
        Ok(())
    }
}

// Read scope logic
#[derive(PartialEq, Debug, Queryable, Identifiable)]
#[table_name = "read_grant_scope"]
pub struct ReadScope {
    pub id: i32,
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub signature: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "read_grant_scope"]
pub struct NewReadScope {
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub signature: Vec<u8>,
}

impl ReadScope {
    pub fn new(code: &str, application: &Application, account: &UnlockedAccount) -> NewReadScope{
        
        let mut scope = NewReadScope {
            application_id:        application.id,
            application_code:      application.code.clone(),
            code:                  code.to_owned(),
            display_name:          None,
            description:           None,
            signature: Vec::new(),
        };

        scope.signature = account.sign_record(&scope);

        scope
    }

    pub fn load_codes(codes: Vec<String>, application: &Application, connection: &MyConnection) -> CommonResult<Vec<ReadScope>> {
        Ok(
            read_grant_scope::table
            .filter( read_grant_scope::application_id.eq(application.id))
            .filter( read_grant_scope::code.eq(any(codes)))
            .get_results(connection)?
            )
    }

    pub fn delete(&mut self, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(read_grant_scope::table.filter(read_grant_scope::id.eq(self.id))).execute(connection)?;
        Ok(())
    }
}

impl Signable for NewReadScope {
    fn record_hash(&self) -> [u8; 32] {
       secure_hash(&[
                   self.application_code.as_bytes(),
                   self.code.as_bytes(), 
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl Signable for ReadScope {
    fn record_hash(&self) -> [u8; 32] {
       secure_hash(&[
                   self.application_code.as_bytes(),
                   self.code.as_bytes(), 
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl NewReadScope {
    pub fn save(self, connection: &MyConnection) -> CommonResult<ReadScope> {
        Ok(diesel::insert_into(read_grant_scope::table).values(self).get_result(connection)?)
    }
}
