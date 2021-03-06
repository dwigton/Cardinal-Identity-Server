use chrono::NaiveDateTime;
use chrono::{Duration, Utc};
use crate::database::schema::read_authorization;
use crate::database::schema::read_grant_key;
use crate::database::MyConnection;
use diesel::prelude::*;
use crate::encryption::byte_encryption::encrypt_32;
use crate::encryption::exchange_key::{EphemeralKey, ExchangeKey};
use crate::encryption::{hash_by_parts, as_256, as_512, random_int_256};
use crate::error::CommonResult;
use crate::model::account::UnlockedAccount;
use crate::model::{Signed, Signable};
use crate::model::{Certified, Certifiable};
use crate::model::client::Client;
use crate::model::read_scope::{ReadScope, UnlockedReadScope};
use crate::model::certificate::{Certificate, CertData};
use crate::model::Scope;

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
    pub signing_key: Vec<u8>,
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
    pub signing_key: Vec<u8>,
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
    fn data(&self) -> CertData {
        CertData{
            signing_key: *as_256(&self.signing_key),
            public_key: *as_256(&self.public_key),
            scope: Scope::Write{
                application: self.application_code.clone(),
                grant: self.read_grant_code.clone(),
            },
            expiration_date: self.expiration_date.clone(),
        }
    }

    fn certify(&self, authorizing_key: Vec<u8>, signature: Vec<u8>) -> NewReadGrantKey {
        NewReadGrantKey {
            read_grant_scope_id: self.read_grant_scope_id,
            public_key: self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            private_key_salt: self.private_key_salt.clone(),
            expiration_date: self.expiration_date,
            signature,
            application_code: self.application_code.clone(),
            read_grant_code: self.read_grant_code.clone(),
            signing_key: authorizing_key,
        }
    }
}

impl Certified for NewReadGrantKey {
    fn certificate(&self) -> Certificate {
        Certificate {
            data: CertData {
                signing_key:     *as_256(&self.signing_key),
                public_key:      *as_256(&self.public_key),
                scope:           Scope::Read{
                    application: self.application_code.clone(),
                    grant: self.read_grant_code.clone(),
                },
                expiration_date: self.expiration_date,
            },
            signature: *as_512(&self.signature),
        }
    }
}

impl NewReadGrantKey {
    pub fn to_insertable(&self) -> InsertReadGrantKey {
        InsertReadGrantKey {
            read_grant_scope_id:   self.read_grant_scope_id,
            public_key:            self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            private_key_salt:      self.private_key_salt.clone(),
            expiration_date:       self.expiration_date,
            signature:             self.signature.clone(),
        }
    }

    pub fn save(&self, connection: &MyConnection) -> CommonResult<()> {
        diesel::insert_into(read_grant_key::table)
            .values(self.to_insertable())
            .execute(connection)?;

        Ok(())
    }
}

pub struct UnsignedReadAuthorization {
    pub client_id: Vec<u8>,
    pub read_grant_key_id: i32,
    pub encrypted_access_key: Vec<u8>,
    pub public_key: Vec<u8>,
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

impl Signable<ReadAuthorization> for UnsignedReadAuthorization {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[
            &self.client_id,
            &self.read_grant_key_id.to_le_bytes(),
            &self.encrypted_access_key,
            &self.public_key,
        ])
    }

    fn sign(&self, signature: Vec<u8>) -> ReadAuthorization {
        ReadAuthorization {
            client_id: self.client_id.clone(),
            read_grant_key_id: self.read_grant_key_id,
            encrypted_access_key: self.encrypted_access_key.clone(),
            public_key: self.public_key.clone(),
            signature,
        }
    }
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
            .execute(connection)?;
        Ok(())
    }

    pub fn load_all_for_client(client: &Client, connection: &MyConnection) -> CommonResult<Vec<ReadAuthorization>> {
        Ok(read_authorization::table
            .filter(read_authorization::client_id.eq(&client.client_id))
            .get_results(connection)?)
    }

    pub fn load_by_key_client(key: &UnlockedReadGrantKey, client: &Client, connection: &MyConnection) -> CommonResult<ReadAuthorization> {
        Ok(read_authorization::table
            .filter(read_authorization::read_grant_key_id.eq(&key.id))
            .filter(read_authorization::client_id.eq(&client.client_id))
            .get_result(connection)?)
    }

    pub fn load_all_for_grant(grant: &ReadGrantKey, connection: &MyConnection) -> CommonResult<Vec<ReadAuthorization>> {
        Ok(read_authorization::table
            .filter(read_authorization::read_grant_key_id.eq(&grant.id))
            .get_results(connection)?)
    }

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(read_authorization::table
                       .filter(read_authorization::client_id.eq(self.client_id))
                       .filter(read_authorization::read_grant_key_id.eq(self.read_grant_key_id))
                       )
            .execute(connection)?;

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

        let new_key = UncertifiedReadGrantKey {
            read_grant_scope_id: scope.id,
            public_key,
            encrypted_private_key,
            private_key_salt: salt.to_vec(),
            expiration_date,
            application_code: scope.application_code.clone(),
            read_grant_code: scope.code.clone(),
            signing_key: account.public_key.clone(),
        };

        account.certify_record(&new_key)
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

    pub fn load_all_for_scope(scope: &ReadScope, connection: &MyConnection) -> CommonResult<Vec<ReadGrantKey>> {
        Ok(read_grant_key::table
            .filter(read_grant_key::read_grant_scope_id.eq(scope.id))
            .get_results(connection)?)
    }

    pub fn to_unlocked(&self, account: &UnlockedAccount) -> CommonResult<UnlockedReadGrantKey> {
        let encryption_key = account.generate_key(&self.private_key_salt);
        let exchange_key =
            ExchangeKey::from_encrypted(&encryption_key, as_512(&self.encrypted_private_key))?;

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

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        // Delete dependant authorizations
        let authorizations = ReadAuthorization::load_all_for_grant(&self, connection)?;

        for authorization in authorizations {
            authorization.delete(connection)?;
        }

        diesel::delete(read_grant_key::table.filter(read_grant_key::id.eq(self.id)))
            .execute(connection)?;
        Ok(())
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
        let encryption_key = ephemeral.key_gen(*as_256(&client.client_id));
        let access_key = account.generate_key(&self.private_key_salt);
        let encrypted_access_key = encrypt_32(&encryption_key, &access_key).to_vec();

        let new_authorization = UnsignedReadAuthorization {
            client_id: client.client_id.clone(),
            read_grant_key_id: self.id,
            encrypted_access_key,
            public_key,
        };

        account.sign_record(&new_authorization).save(connection)?;

        Ok(())
    }

    pub fn revoke(&self, client: &Client, connection: &MyConnection) -> CommonResult<()> {
        ReadAuthorization::load_by_key_client(self, client, connection)?.delete(connection)
    }
}

