use database::schema::client;
use database::MyConnection;
use diesel::prelude::*;
use diesel::{update, insert_into, result, delete};
use encryption::signing_key::SigningKey;
use encryption::{hash_password, check_password, random_int_256, hash_salted_password, pk_bytes, secure_hash};
use error::{CommonResult, CommonError};
use base64::{encode, decode};
use encryption::Sha512Trunc256;
use model::application::PortableApplication;
use clear_on_drop::clear::Clear;

pub struct PortableClient {
}

pub struct NewClient {
    pub name: String,
    pub client_id: Vec<u8>,
    pub application_id: i32,
}

pub struct Client {
    pub id: i32,
    pub name: String,
    pub client_id: Vec<u8>,
    pub application_id: i32,
}

pub struct UnlockedClient {
    pub id: i32,
    pub name: String,
    pub client_id: Vec<u8>,
    pub application_id: i32,
}

impl Client {
    /// loads or creates a new client in the database
    pub fn load_or_create(user_id: i32, client_name: &str, connection: &PgConnection) -> CommonResult<ClientApp> {
        let result = match ClientApp::load_by_name(user_id, client_name, connection) {
            Ok(c) => c,
            Err(_) => {
                let mut client = ClientApp::new(user_id, client_name);
                client.save(connection)?;
                client
            },
        };

        Ok(result)
    }
}
