use database::schema::client;
use database::MyConnection;
use diesel::prelude::*;
use diesel::{update, insert_into, result, delete};
use error::CommonResult;
use model::Signable;
use model::account::UnlockedAccount;
use model::application::Application;
use encryption::exchange_key::ExchangeKey;
use encryption::hash_by_parts;
use encryption::byte_encryption::decrypt_32;

#[derive(Insertable)]
#[table_name = "client"]
pub struct NewClient {
    pub client_id: Vec<u8>,
    pub application_id: i32,
    pub application_code: String,
    pub signature: Vec<u8>,
}

#[derive(Queryable)]
pub struct Client {
    pub client_id: Vec<u8>,
    pub application_id: i32,
    pub application_code: String,
    pub signature: Vec<u8>,
}

pub struct UnlockedClient {
    pub client_id: Vec<u8>,
    pub application_id: i32,
    pub application_code: String,
    pub signature: Vec<u8>,
    exchange_key: ExchangeKey,
}

impl Signable for NewClient {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
                   self.application_code.as_bytes(), 
                   &self.client_id
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl Signable for Client {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
                   self.application_code.as_bytes(), 
                   &self.client_id
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl Client {
    pub fn new(account: &UnlockedAccount, application: &Application) -> ([u8; 32], NewClient) {
        let key = ExchangeKey::new();

        let mut client = NewClient {
            application_id: application.id,
            application_code: application.code.clone(),
            client_id: key.public_key().to_vec(),
            signature: Vec::new(),
        };

        client.signature = account.sign_record(&client);
        
        (key.private_key(), client)
    }

    pub fn to_unlocked(&self, secret_token: [u8; 32]) -> UnlockedClient {
        let exchange_key = ExchangeKey::from_key(secret_token);

        UnlockedClient {
            application_id: self.application_id,
            application_code: self.application_code.clone(),
            client_id: self.client_id.clone(),
            signature: self.signature.clone(),
            exchange_key,
        }
    }
}

impl NewClient {
    pub fn save(&self, connection: &MyConnection) -> CommonResult<Client> {
        Ok(diesel::insert_into(client::table).values(self).get_result(connection)?)
    }
}

impl UnlockedClient {
    pub fn unlock_key(&self, public_key: &[u8; 32], encrypted_key: &[u8; 64]) -> CommonResult<[u8; 32]> {
        let key = self.exchange_key.key_gen(*public_key);
        Ok(decrypt_32(encrypted_key, &key)?)
    }
}
