use crate::database::schema::client;
use crate::database::schema::application;
use crate::database::MyConnection;
use diesel::prelude::*;
use crate::encryption::byte_encryption::decrypt_32;
use crate::encryption::exchange_key::ExchangeKey;
use crate::encryption::hash_by_parts;
use crate::error::CommonResult;
use crate::model::account::UnlockedAccount;
use crate::model::application::Application;
use crate::model::{Signable, Signed};
use crate::model::read_authorization::ReadAuthorization;
use crate::model::write_authorization::WriteAuthorization;
use std::convert::From;

pub struct UnsignedClient {
    pub client_id: Vec<u8>,
    pub application_id: i32,
    pub application_code: String,
}

pub struct NewClient {
    pub client_id: Vec<u8>,
    pub application_id: i32,
    pub application_code: String,
    pub signature: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "client"]
pub struct InsertClient {
    pub client_id: Vec<u8>,
    pub application_id: i32,
    pub signature: Vec<u8>,
}

#[derive(Queryable, Serialize)]
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

impl From<NewClient> for InsertClient {
    fn from(item: NewClient) -> InsertClient {
        InsertClient {
            client_id: item.client_id,
            application_id: item.application_id,
            signature: item.signature,
        }
    }
}

impl Signable<NewClient> for UnsignedClient {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[self.application_code.as_bytes(), &self.client_id])
    }

    fn sign(&self, signature: Vec<u8>) -> NewClient {
        NewClient {
            client_id: self.client_id.clone(),
            application_id: self.application_id,
            application_code: self.application_code.clone(),
            signature,
        }
    }
}

impl Signed for NewClient {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[self.application_code.as_bytes(), &self.client_id])
    }

    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl Signed for Client {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[self.application_code.as_bytes(), &self.client_id])
    }

    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl Signed for UnlockedClient {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[self.application_code.as_bytes(), &self.client_id])
    }

    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl Client {
    pub fn new(account: &UnlockedAccount, application: &Application) -> ([u8; 32], NewClient) {
        let key = ExchangeKey::new();

        let client = UnsignedClient {
            application_id: application.id,
            application_code: application.code.clone(),
            client_id: key.public_key().to_vec(),
        };

        let new_client = account.sign_record(&client);

        (key.private_key(), new_client)
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

    pub fn load_id(
        id: Vec<u8>,
        connection: &MyConnection,
    ) -> CommonResult<Client> {
        Ok(client::table
            .inner_join(application::table)
            .filter(client::client_id.eq(id))
            .select((
                    client::client_id,
                    client::application_id,
                    application::code,
                    client::signature
                    ))
            .get_result(connection)?)
    }

    pub fn load_all_for_application(
        application: &Application,
        connection: &MyConnection,
    ) -> CommonResult<Vec<Client>> {
        Ok(client::table
            .inner_join(application::table)
            .filter(client::application_id.eq(application.id))
            .select((
                    client::client_id,
                    client::application_id,
                    application::code,
                    client::signature
                    ))
            .get_results(connection)?)
    }

    pub fn load_all(
        connection: &MyConnection,
    ) -> CommonResult<Vec<Client>> {
        Ok(client::table
            .inner_join(application::table)
            .select((
                    client::client_id,
                    client::application_id,
                    application::code,
                    client::signature
                    ))
            .get_results(connection)?)
    }

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        // First delete all read authorizations pointing to this client.
        let read_auths = ReadAuthorization::load_all_for_client(&self, connection)?;

        for read_auth in read_auths {
            read_auth.delete(connection)?;
        }

        // Delete all write authorizations pointing to this client.
        let write_auths = WriteAuthorization::load_all_for_client(&self, connection)?;

        for write_auth in write_auths {
            write_auth.delete(connection)?;
        }

        // Finally delete the client.
        diesel::delete(client::table.filter(client::client_id.eq(self.client_id)))
            .execute(connection)?;

        Ok(())
    }
}

impl NewClient {
    pub fn save(self, connection: &MyConnection) -> CommonResult<Client> {
        let client_id: Vec<u8> = 
            diesel::insert_into(client::table)
            .values(InsertClient::from(self))
            .returning(client::client_id)
            .get_result(connection)?;

        Ok(Client::load_id(client_id, connection)?)
    }
}

impl UnlockedClient {
    pub fn unlock_key(
        &self,
        public_key: &[u8; 32],
        encrypted_key: &[u8; 64],
    ) -> CommonResult<[u8; 32]> {
        let key = self.exchange_key.key_gen(*public_key);
        Ok(decrypt_32(encrypted_key, &key)?)
    }
}
