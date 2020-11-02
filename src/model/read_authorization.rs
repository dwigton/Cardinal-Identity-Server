use chrono::NaiveDateTime;
use chrono::{Duration, Utc};
use database::schema::read_authorization;
use database::schema::read_grant_key;
use database::schema::write_authorization;
use database::MyConnection;
use diesel::prelude::*;
use diesel::insertable::Insertable;
use encryption::byte_encryption::encrypt_32;
use encryption::exchange_key::{EphemeralKey, ExchangeKey};
use encryption::{hash_by_parts, to_256, to_512, random_int_256};
use error::CommonResult;
use model::account::UnlockedAccount;
use model::{Signed};
use model::{Certified, Certifiable};
use model::client::Client;
use model::read_scope::{ReadScope, UnlockedReadScope};
use model::certificate::{Certificate, CertData};
use model::Scope;


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

#[derive(PartialEq, Debug, Queryable, Identifiable)]
#[table_name = "read_grant_key"]
pub struct ReadGrantKey {
    pub id: i32,
    pub read_grant_scope_id: i32,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
}

pub struct UncertifiedReadGrantKey {
    pub read_grant_scope_id: i32,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub application_code: String,
    pub read_grant_code: String,
}

#[derive(Insertable)]
#[table_name = "read_grant_key"]
pub struct InsertReadGrantKey {
    pub read_grant_scope_id: i32,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
}

pub struct NewReadGrantKey {
    pub read_grant_scope_id: i32,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
    pub application_code: String,
    pub read_grant_code: String,
    pub signing_key: [u8; 32],
}

pub struct UnlockedReadGrantKey {
    pub id: i32,
    pub read_grant_scope_id: i32,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
    pub exchange_key: ExchangeKey,
}

impl Certifiable<NewReadGrantKey> for UncertifiedReadGrantKey {
}

impl Certified for NewReadGrantKey {
    fn certificate(&self) -> Certificate {
        Certificate {
            data: CertData {
                signing_key:     self.signing_key,
                public_key:      *to_256(&self.public_key),
                scope:           Scope::Read{
                    application: self.application_code,
                    grant: self.read_grant_code,
                },
                expiration_date: self.expiration_date,
            },
            signature: *to_256(&self.signature),
        }
    }
}

impl NewReadGrantKey {
    pub fn to_insertable(&self) -> InsertReadGrantKey {
        InsertReadGrantKey {
            read_grant_scope_id:   self.read_grant_scope_id,
            public_key:            self.public_key,
            encrypted_private_key: self.encrypted_private_key,
            private_key_salt:      self.private_key_salt,
            expiration_date:       self.expiration_date,
            signature:             self.signature,
        }
    }

    pub fn save(&self, connection: &MyConnection) -> CommonResult<()> {
        diesel::insert_into(read_grant_key::table)
            .values(self.to_insertable())
            .execute(connection)?;

        Ok(())
    }
}

#[derive(PartialEq, Debug, Queryable, Insertable)]
#[table_name = "read_authorization"]
pub struct ReadAuthorization {
    pub client_id: Vec<u8>,
    pub read_grant_key_id: i32,
    pub encrypted_access_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Signed for ReadAuthorization {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[
            &self.client_id,
            &self.read_grant_key_id.to_le_bytes(),
            &self.encrypted_access_key,
            &self.public_key,
        ])
    }

    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl ReadAuthorization {
    pub fn save(&self, connection: &MyConnection) -> CommonResult<()> {
        diesel::insert_into(read_authorization::table)
            .values(self)
            .execute(connection);
        Ok(())
    }
}

impl ReadGrantKey {
    pub fn new(scope: &UnlockedReadScope, account: &UnlockedAccount) -> NewReadGrantKey {
        let salt = random_int_256();

        // expire in one year as default
        let expiration_date = (Utc::now() + Duration::days(365)).naive_utc();
        let exchange_key = ExchangeKey::new();
        let encryption_key = account.generate_key(&salt);
        let encrypted_private_key = exchange_key.encrypted_private_key(&encryption_key).to_vec();
        let public_key = exchange_key.public_key().to_vec();

        let mut new_key = UncertifiedReadGrantKey {
            read_grant_scope_id: scope.id,
            public_key,
            encrypted_private_key,
            private_key_salt: salt.to_vec(),
            expiration_date,
            application_code: scope.application_code.clone(),
            read_grant_code: scope.code.clone(),
        };

        account.sign_record(&new_key)
    }

    pub fn load_with_account(
        scope: &ReadScope,
        account: &UnlockedAccount,
        connection: &MyConnection,
    ) -> CommonResult<Vec<UnlockedReadGrantKey>> {
        let locked_keys: Vec<ReadGrantKey> = read_grant_key::table
            .filter(read_grant_key::read_grant_scope_id.eq(scope.id))
            .get_results(connection)?;

        let mut unlocked_keys = Vec::new();

        for locked_key in locked_keys {
            unlocked_keys.push(locked_key.to_unlocked(account)?);
        }

        Ok(unlocked_keys)
    }

    pub fn to_unlocked(&self, account: &UnlockedAccount) -> CommonResult<UnlockedReadGrantKey> {
        let encryption_key = account.generate_key(&self.private_key_salt);
        let exchange_key =
            ExchangeKey::from_encrypted(&encryption_key, to_512(&self.encrypted_private_key))?;

        Ok(UnlockedReadGrantKey {
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
    pub fn authorize(
        &self,
        account: &UnlockedAccount,
        client: &Client,
        connection: &MyConnection,
    ) -> CommonResult<()> {
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

