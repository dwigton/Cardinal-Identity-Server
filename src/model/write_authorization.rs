use database::schema::write_authorization;
use database::MyConnection;
use diesel::prelude::*;
use error::CommonResult;
use model::{Signable, Signed};
use model::client::Client;
use model::write_scope::LockedWriteScope;
use model::write_scope::UnlockedWriteScope;
use encryption::hash_by_parts;


#[derive(PartialEq, Debug, Queryable)]
pub struct WriteAuthorization {
    pub client_id: Vec<u8>,
    pub write_grant_scope_id: i32,
    pub encrypted_access_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "write_authorization"]
pub struct NewWriteAuthorization {
    pub client_id: Vec<u8>,
    pub write_grant_scope_id: i32,
    pub encrypted_access_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct UnsignedWriteAuthorization {
    pub client_id: Vec<u8>,
    pub write_grant_scope_id: i32,
    pub encrypted_access_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Signable<NewWriteAuthorization> for UnsignedWriteAuthorization {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[
            &self.client_id,
            &self.write_grant_scope_id.to_le_bytes(),
            &self.encrypted_access_key,
            &self.public_key,
        ])
    }

    fn sign(&self, signature: Vec<u8>) -> NewWriteAuthorization {
        NewWriteAuthorization {
            client_id: self.client_id.clone(),
            write_grant_scope_id: self.write_grant_scope_id,
            encrypted_access_key: self.encrypted_access_key.clone(),
            public_key: self.public_key.clone(),
            signature,
        }
    }
}

impl Signed for NewWriteAuthorization {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[
            &self.client_id,
            &self.write_grant_scope_id.to_le_bytes(),
            &self.encrypted_access_key,
            &self.public_key,
        ])
    }

    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl Signed for WriteAuthorization {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[
            &self.client_id,
            &self.write_grant_scope_id.to_le_bytes(),
            &self.encrypted_access_key,
            &self.public_key,
        ])
    }

    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl NewWriteAuthorization {
    pub fn save(&self, connection: &MyConnection) -> CommonResult<WriteAuthorization> {
        Ok(diesel::insert_into(write_authorization::table)
            .values(self)
            .get_result(connection)?)
    }
}

impl WriteAuthorization {
    pub fn load_all_for_client(client: &Client, connection: &MyConnection) -> CommonResult<Vec<WriteAuthorization>> {
        Ok(write_authorization::table
            .filter(write_authorization::client_id.eq(&client.client_id))
            .get_results(connection)?)
    }

    pub fn load_all_for_scope(scope: &LockedWriteScope, connection: &MyConnection) -> CommonResult<Vec<WriteAuthorization>> {
        Ok(write_authorization::table
            .filter(write_authorization::write_grant_scope_id.eq(&scope.id))
            .get_results(connection)?)
    }

    pub fn load_scope_client(scope: &UnlockedWriteScope, client: &Client, connection: &MyConnection) -> CommonResult<WriteAuthorization> {
        Ok(write_authorization::table
            .filter(write_authorization::client_id.eq(&client.client_id))
            .filter(write_authorization::write_grant_scope_id.eq(&scope.id))
            .get_result(connection)?)
    }

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(write_authorization::table
                       .filter(write_authorization::client_id.eq(self.client_id))
                       .filter(write_authorization::write_grant_scope_id.eq(self.write_grant_scope_id))
                       )
            .execute(connection)?;

        Ok(())
    }
}
