use database::schema::write_grant_scope;
use database::schema::write_authorization;
use database::schema::read_grant_scope;
use database::schema::read_grant_key;
use database::schema::read_authorization;
use database::MyConnection;
use diesel::prelude::*;
use diesel::expression::dsl::any;
use chrono::NaiveDateTime;
use chrono::{Duration, Utc};
use model::Signable;
use model::account::UnlockedAccount;
use model::application::Application;
use model::client::{Client, UnlockedClient};
use error::{CommonResult, CommonError};
use encryption::{hash_by_parts, random_int_256, to_256, to_512};
use encryption::signing_key::SigningKey;
use encryption::exchange_key::{ExchangeKey, EphemeralKey};
use encryption::byte_encryption::encrypt_32;

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
    signing_key: SigningKey,
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

    pub fn load_unlocked (codes: &[String], account: &UnlockedAccount, application: &Application, connection: &MyConnection) 
        -> CommonResult<Vec<UnlockedWriteScope>> {
       
            let locked_scopes: Vec<LockedWriteScope> = 
                write_grant_scope::table
                .filter( write_grant_scope::application_id.eq(application.id))
                .filter( write_grant_scope::code.eq(any(codes)))
                .get_results(connection)?;

            let mut scopes = Vec::new();

            for locked_scope in locked_scopes {
                if !account.verify_record(&locked_scope) {
                    return Err(CommonError::FailedVerification(None));
                }

                let scope = locked_scope.unlock_by_account(account)?;
                scopes.push(scope);
            }

            Ok(scopes)
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

impl UnlockedWriteScope {
    pub fn authorize(&self, account: &UnlockedAccount, client: &Client, connection: &MyConnection) -> CommonResult<()> {

        let ephemeral = EphemeralKey::new();
        let public_key = ephemeral.public_key().to_vec();
        let encryption_key = ephemeral.key_gen(*to_256(&client.client_id)); 
        let access_key = account.generate_key(&self.private_key_salt);
        let encrypted_access_key = encrypt_32(&encryption_key, &access_key).to_vec();
        

        let mut new_authorization = NewWriteAuthorization {
            client_id: client.client_id.clone(),
            write_grant_scope_id: self.id,
            public_key,
            encrypted_access_key,
            signature: Vec::new(),
        };

        new_authorization.signature = account.sign_record(&new_authorization);

        new_authorization.save(connection)?;

        Ok(())
    }
}

impl Signable for NewWriteScope {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
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
       hash_by_parts(&[
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

    fn to_unlocked(&self, encryption_key: &[u8; 32]) -> CommonResult<UnlockedWriteScope> {
        let signing_key = SigningKey::from_encrypted(&encryption_key, to_256(&self.public_key), to_512(&self.encrypted_private_key))?;

        Ok (UnlockedWriteScope {
            id:                    self.id,
            application_id:        self.application_id,
            application_code:      self.application_code.clone(),
            code:                  self.code.clone(),
            display_name:          self.display_name.clone(),
            description:           self.description.clone(),
            public_key:            self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            private_key_salt:      self.private_key_salt.clone(),
            expiration_date:       self.expiration_date.clone(),
            signature:             self.signature.clone(),
            signing_key,
        })
    }

    pub fn unlock_by_account(&self, account: &UnlockedAccount) -> CommonResult<UnlockedWriteScope> {
        let encryption_key = account.generate_key(to_256(&self.private_key_salt));
        self.to_unlocked(&encryption_key)
    }

    pub fn unlock_by_client(&self, client: &UnlockedClient, authorization: &WriteAuthorization) -> CommonResult<UnlockedWriteScope> {
        let encryption_key = client.unlock_key(
            to_256(&authorization.public_key), 
            to_512(&authorization.encrypted_access_key)
            )?;

        let signing_key = SigningKey::from_encrypted(
            &encryption_key, 
            to_256(&self.public_key), 
            to_512(&self.encrypted_private_key)
            )?;

        Ok (UnlockedWriteScope {
            id:                    self.id,
            application_id:        self.application_id,
            application_code:      self.application_code.clone(),
            code:                  self.code.clone(),
            display_name:          self.display_name.clone(),
            description:           self.description.clone(),
            public_key:            self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            private_key_salt:      self.private_key_salt.clone(),
            expiration_date:       self.expiration_date.clone(),
            signature:             self.signature.clone(),
            signing_key,
        })
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

pub struct UnlockedReadScope {
    pub id: i32,
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub signature: Vec<u8>,
    read_keys: Vec<UnlockedReadGrantKey>,
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

    pub fn load_codes(
        codes: Vec<String>, 
        account: &UnlockedAccount, 
        application: &Application, 
        connection: &MyConnection) -> CommonResult<Vec<ReadScope>> {
            let scopes: Vec<ReadScope> = read_grant_scope::table
            .filter( read_grant_scope::application_id.eq(application.id))
            .filter( read_grant_scope::code.eq(any(codes)))
            .get_results(connection)?;

            for scope in &scopes {
                if ! account.verify_record(scope) {
                    return Err(CommonError::FailedVerification(Some("Write scope failed verification.".to_owned())));
                }
            }

            Ok(scopes)
    }

    pub fn to_unlocked(&self, account: &UnlockedAccount, connection: &MyConnection) -> CommonResult<UnlockedReadScope>{
        let read_keys = ReadGrantKey::load_with_account(self, account, connection)?;

        Ok(UnlockedReadScope{
            id: self.id,
            application_id: self.application_id,
            application_code: self.application_code.clone(),
            code: self.code.clone(),
            display_name: self.display_name.clone(),
            description: self.description.clone(),
            signature: self.signature.clone(),
            read_keys: read_keys,
        })
    }


    pub fn delete(&mut self, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(read_grant_scope::table.filter(read_grant_scope::id.eq(self.id))).execute(connection)?;
        Ok(())
    }
}

impl UnlockedReadScope {
    pub fn authorize(&self, account: &UnlockedAccount, client: &Client, connection: &MyConnection) -> CommonResult<()> {

        for read_key in &self.read_keys {
            read_key.authorize(account, client, connection)?;
        }

        Ok(())
    }
}

impl Signable for NewReadScope {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
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
       hash_by_parts(&[
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

#[derive(PartialEq, Debug, Queryable)]
pub struct WriteAuthorization {
    client_id: Vec<u8>,
    write_grant_scope_id: i32,
    encrypted_access_key: Vec<u8>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "write_authorization"]
pub struct NewWriteAuthorization {
    client_id: Vec<u8>,
    write_grant_scope_id: i32,
    encrypted_access_key: Vec<u8>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl Signable for NewWriteAuthorization {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
                   &self.client_id,
                   &self.write_grant_scope_id.to_le_bytes(),
                   &self.encrypted_access_key,
                   &self.public_key
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl Signable for WriteAuthorization {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
                   &self.client_id,
                   &self.write_grant_scope_id.to_le_bytes(),
                   &self.encrypted_access_key,
                   &self.public_key
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl NewWriteAuthorization {
    pub fn save(&self, connection: &MyConnection) -> CommonResult<WriteAuthorization> {
        Ok(
            diesel::insert_into(write_authorization::table)
            .values(self)
            .get_result(connection)?
            )
    }
}

#[derive(PartialEq, Debug, Queryable, Identifiable)]
#[table_name = "read_grant_key"]
pub struct ReadGrantKey {
    id: i32,
    read_grant_scope_id: i32,
    public_key: Vec<u8>,
    encrypted_private_key: Vec<u8>,
    private_key_salt: Vec<u8>,
    expiration_date: NaiveDateTime,
    signature: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "read_grant_key"]
pub struct NewReadGrantKey {
    read_grant_scope_id: i32,
    public_key: Vec<u8>,
    encrypted_private_key: Vec<u8>,
    private_key_salt: Vec<u8>,
    expiration_date: NaiveDateTime,
    signature: Vec<u8>,
}

pub struct UnlockedReadGrantKey {
    id: i32,
    read_grant_scope_id: i32,
    public_key: Vec<u8>,
    encrypted_private_key: Vec<u8>,
    private_key_salt: Vec<u8>,
    expiration_date: NaiveDateTime,
    signature: Vec<u8>,
    exchange_key: ExchangeKey,
}

#[derive(PartialEq, Debug, Queryable, Insertable)]
#[table_name = "read_authorization"]
pub struct ReadAuthorization {
    client_id: Vec<u8>,
    read_grant_key_id: i32,
    encrypted_access_key: Vec<u8>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl Signable for ReadAuthorization {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
                   &self.client_id,
                   &self.read_grant_key_id.to_le_bytes(),
                   &self.encrypted_access_key,
                   &self.public_key
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl ReadAuthorization {
    pub fn save(&self, connection: &MyConnection) -> CommonResult<()> {
        diesel::insert_into(read_authorization::table).values(self).execute(connection);
        Ok(())
    }
}

impl ReadGrantKey {

    pub fn load_with_account(
        scope: &ReadScope,
        account: &UnlockedAccount,
        connection: &MyConnection) -> CommonResult<Vec<UnlockedReadGrantKey>>
    {
        let locked_keys: Vec<ReadGrantKey> = read_grant_key::table
                .filter( read_grant_key::read_grant_scope_id.eq(scope.id))
                .get_results(connection)?;

        let mut unlocked_keys = Vec::new();

        for locked_key in locked_keys {
            unlocked_keys.push(locked_key.to_unlocked(account)?);
        }

        Ok(unlocked_keys)

    }

    pub fn to_unlocked (&self, account: &UnlockedAccount) -> CommonResult<UnlockedReadGrantKey> {
        let encryption_key = account.generate_key(&self.private_key_salt);
        let exchange_key = ExchangeKey::from_encrypted(&encryption_key, to_512(&self.encrypted_private_key))?;

        Ok( UnlockedReadGrantKey {
            id: self.id,
            read_grant_scope_id: self.read_grant_scope_id,
            public_key: self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            private_key_salt: self.private_key_salt.clone(),
            expiration_date: self.expiration_date.clone(),
            signature: self.signature.clone(),
            exchange_key,
        })
    }
}

impl UnlockedReadGrantKey {
    pub fn authorize(&self, account: &UnlockedAccount, client: &Client, connection: &MyConnection) -> CommonResult<()> {
        let ephemeral = EphemeralKey::new();
        let public_key = ephemeral.public_key().to_vec();
        let encryption_key = ephemeral.key_gen(*to_256(&client.client_id)); 
        let access_key = account.generate_key(&self.private_key_salt);
        let encrypted_access_key = encrypt_32(&encryption_key, &access_key).to_vec();
        

        let mut new_authorization = ReadAuthorization {
            client_id: client.client_id.clone(),
            read_grant_key_id: self.id,
            encrypted_access_key,
            public_key,
            signature: Vec::new(),
        };

        new_authorization.signature = account.sign_record(&new_authorization);

        new_authorization.save(connection)?;

        Ok(())
    }
}
