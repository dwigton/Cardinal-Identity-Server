use chrono::NaiveDateTime;
use chrono::{Duration, Utc};
use database::schema::{write_grant_scope, application, account};
use database::MyConnection;
use diesel::expression::dsl::any;
use diesel::prelude::*;
use encryption::byte_encryption::encrypt_32;
use encryption::exchange_key::EphemeralKey;
use encryption::signing_key::SigningKey;
use encryption::{random_int_256, to_256, to_512};
use error::{CommonError, CommonResult};
use model::account::UnlockedAccount;
use model::application::Application;
use model::client::{Client, UnlockedClient};
use model::{Certifiable, Scope};
use model::write_authorization::{UnsignedWriteAuthorization, WriteAuthorization};
use model::certificate::{CertData, Certificate};
use model::Certified;

pub struct WriteScope {}

pub struct UnlockedWriteScope {
    pub id: i32,
    pub application_id: i32,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
    pub application_code: String,
    pub signing_key: SigningKey,
}

pub struct UncertifiedWriteScope {
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
}

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
    pub signing_key: [u8; 32],
}

#[derive(Insertable)]
#[table_name = "write_grant_scope"]
pub struct InsertWriteScope {
    pub application_id: i32,
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
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_salt: Vec<u8>,
    pub expiration_date: NaiveDateTime,
    pub signature: Vec<u8>,
    pub application_code: String,
    pub signing_key: Vec<u8>,
}

impl InsertWriteScope {
    fn new(source: &NewWriteScope) -> InsertWriteScope {
        InsertWriteScope {
            application_id: source.application_id,
            code: source.code,
            display_name: source.display_name,
            description: source.description,
            public_key: source.public_key,
            encrypted_private_key: source.encrypted_private_key,
            private_key_salt: source.private_key_salt,
            expiration_date: source.expiration_date,
            signature: source.signature,
        }
    }
}

impl WriteScope {
    pub fn new(code: &str, application: &Application, account: &UnlockedAccount) -> NewWriteScope {
        let salt = random_int_256();

        // expire in one year as default
        let expiration_date = (Utc::now() + Duration::days(365)).naive_utc();
        let signing_key = SigningKey::new();
        let encryption_key = account.generate_key(&salt);
        let encrypted_private_key = signing_key.encrypted_private_key(&encryption_key).to_vec();
        let public_key = signing_key.public_key().to_vec();

        let mut scope = UncertifiedWriteScope {
            application_id: application.id,
            application_code: application.code.clone(),
            code: code.to_owned(),
            display_name: None,
            description: None,
            public_key,
            encrypted_private_key,
            private_key_salt: salt.to_vec(),
            expiration_date,
        };

        account.certify_record(&scope)
    }

    pub fn load_unlocked(
        codes: &[String],
        account: &UnlockedAccount,
        application: &Application,
        connection: &MyConnection,
    ) -> CommonResult<Vec<UnlockedWriteScope>> {
        let locked_scopes: Vec<LockedWriteScope> = write_grant_scope::table
            .inner_join(application::table.inner_join(account::table))
            .filter(write_grant_scope::application_id.eq(application.id))
            .filter(write_grant_scope::code.eq(any(codes)))
            .select((
                    write_grant_scope::id,
                    write_grant_scope::application_id,
                    write_grant_scope::code,
                    write_grant_scope::display_name,
                    write_grant_scope::description,
                    write_grant_scope::public_key,
                    write_grant_scope::encrypted_private_key,
                    write_grant_scope::private_key_salt,
                    write_grant_scope::expiration_date,
                    write_grant_scope::signature,
                    application::code,
                    account::public_key
                    ))
            .load::<LockedWriteScope>(connection)?;

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

    pub fn load_codes(
        codes: Vec<String>,
        application: &Application,
        connection: &MyConnection,
    ) -> CommonResult<Vec<LockedWriteScope>> {
        Ok(write_grant_scope::table
            .inner_join(application::table.inner_join(account::table))
            .filter(write_grant_scope::application_id.eq(application.id))
            .filter(write_grant_scope::code.eq(any(codes)))
            .select((
                    write_grant_scope::id,
                    write_grant_scope::application_id,
                    write_grant_scope::code,
                    write_grant_scope::display_name,
                    write_grant_scope::description,
                    write_grant_scope::public_key,
                    write_grant_scope::encrypted_private_key,
                    write_grant_scope::private_key_salt,
                    write_grant_scope::expiration_date,
                    write_grant_scope::signature,
                    application::code,
                    account::public_key
                    ))
            .get_results(connection)?)
    }

    pub fn load_id(
        id: i32,
        connection: &MyConnection,
    ) -> CommonResult<LockedWriteScope> {
        Ok(write_grant_scope::table
            .inner_join(application::table.inner_join(account::table))
            .filter(write_grant_scope::id.eq(id))
            .select((
                    write_grant_scope::id,
                    write_grant_scope::application_id,
                    write_grant_scope::code,
                    write_grant_scope::display_name,
                    write_grant_scope::description,
                    write_grant_scope::public_key,
                    write_grant_scope::encrypted_private_key,
                    write_grant_scope::private_key_salt,
                    write_grant_scope::expiration_date,
                    write_grant_scope::signature,
                    application::code,
                    account::public_key
                    ))
            .get_result(connection)?)
    }
}

impl UnlockedWriteScope {
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

        let mut new_authorization = UnsignedWriteAuthorization {
            client_id: client.client_id.clone(),
            write_grant_scope_id: self.id,
            public_key,
            encrypted_access_key,
        };

        account.sign_record(&new_authorization).save(connection)?;

        Ok(())
    }
}

impl Certified for NewWriteScope {
    fn certificate(&self) -> Certificate {
        Certificate {
            data: CertData{
                signing_key:     self.signing_key,
                public_key:      *to_256(&self.public_key),
                scope:           Scope::Write{
                   application: self.application_code,
                   grant: self.code,
                },
                expiration_date: self.expiration_date,
            },
            signature: *to_256(&self.signature),
        }
    }
}

impl Certifiable<NewWriteScope> for UncertifiedWriteScope {

    fn data(&self) -> CertData {
        CertData{
            // It appears I put crap data here.
            signing_key: [7u8; 32],
            public_key: *to_256(&self.public_key.clone()),
            scope: Scope::Write{
                application: self.application_code.clone(),
                grant: self.code.clone(),
            },
            expiration_date: self.expiration_date.clone(),
        }
    }

    fn certify(&self, authorizing_key: Vec<u8>, signature: Vec<u8>) -> NewWriteScope {
        NewWriteScope {
            application_id: self.application_id,
            application_code: self.application_code,
            code: self.code,
            display_name: self.display_name,
            description: self.description,
            public_key: self.public_key,
            encrypted_private_key: self.encrypted_private_key,
            private_key_salt: self.private_key_salt,
            expiration_date: self.expiration_date,
            signature,
            signing_key: *to_256(&authorizing_key),
        }
    }
}

impl Certified for LockedWriteScope {

    fn certificate(&self) -> Certificate {
        Certificate {
            data: CertData{
                signing_key:     *to_256(&self.signing_key),
                public_key:      *to_256(&self.public_key),
                scope:           Scope::Write{
                   application: self.application_code,
                   grant: self.code,
                },
                expiration_date: self.expiration_date,
            },
            signature: *to_256(&self.signature),
        }
    }
}

impl NewWriteScope {
    pub fn save(self, connection: &MyConnection) -> CommonResult<LockedWriteScope> {
        let record_id: i32 = diesel::insert_into(write_grant_scope::table)
            .values(InsertWriteScope::new(&self))
            .returning(write_grant_scope::id)
            .get_result(connection)?;
        
        Ok(WriteScope::load_id(record_id, connection)?)
    }
}

impl LockedWriteScope {
    pub fn delete(&mut self, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(write_grant_scope::table.filter(write_grant_scope::id.eq(self.id)))
            .execute(connection)?;
        Ok(())
    }

    fn to_unlocked(&self, encryption_key: &[u8; 32]) -> CommonResult<UnlockedWriteScope> {
        let signing_key = SigningKey::from_encrypted(
            &encryption_key,
            to_256(&self.public_key),
            to_512(&self.encrypted_private_key),
        )?;

        Ok(UnlockedWriteScope {
            id: self.id,
            application_id: self.application_id,
            application_code: self.application_code.clone(),
            code: self.code.clone(),
            display_name: self.display_name.clone(),
            description: self.description.clone(),
            public_key: self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            private_key_salt: self.private_key_salt.clone(),
            expiration_date: self.expiration_date.clone(),
            signature: self.signature.clone(),
            signing_key,
        })
    }

    pub fn unlock_by_account(&self, account: &UnlockedAccount) -> CommonResult<UnlockedWriteScope> {
        let encryption_key = account.generate_key(to_256(&self.private_key_salt));
        self.to_unlocked(&encryption_key)
    }

    pub fn unlock_by_client(
        &self,
        client: &UnlockedClient,
        authorization: &WriteAuthorization,
    ) -> CommonResult<UnlockedWriteScope> {
        let encryption_key = client.unlock_key(
            to_256(&authorization.public_key),
            to_512(&authorization.encrypted_access_key),
        )?;

        let signing_key = SigningKey::from_encrypted(
            &encryption_key,
            to_256(&self.public_key),
            to_512(&self.encrypted_private_key),
        )?;

        Ok(UnlockedWriteScope {
            id: self.id,
            application_id: self.application_id,
            application_code: self.application_code.clone(),
            code: self.code.clone(),
            display_name: self.display_name.clone(),
            description: self.description.clone(),
            public_key: self.public_key.clone(),
            encrypted_private_key: self.encrypted_private_key.clone(),
            private_key_salt: self.private_key_salt.clone(),
            expiration_date: self.expiration_date.clone(),
            signature: self.signature.clone(),
            signing_key,
        })
    }
}
