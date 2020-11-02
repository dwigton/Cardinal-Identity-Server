use database::schema::read_grant_scope;
use database::MyConnection;
use diesel::expression::dsl::any;
use diesel::prelude::*;
use error::{CommonError, CommonResult};
use model::account::UnlockedAccount;
use model::application::Application;
use model::{Signable, Signed};
use model::read_authorization::{ReadGrantKey, UnlockedReadGrantKey};
use model::client::Client;
use encryption::hash_by_parts;

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

pub struct UnsignedReadScope {
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
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

impl Signable<NewReadScope> for UnsignedReadScope {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[self.application_code.as_bytes(), self.code.as_bytes()])
    }
}

impl ReadScope {
    pub fn new(code: &str, application: &Application, account: &UnlockedAccount) -> NewReadScope {
        let mut scope = UnsignedReadScope {
            application_id: application.id,
            application_code: application.code.clone(),
            code: code.to_owned(),
            display_name: None,
            description: None,
        };

        account.sign_record(&scope)
    }

    pub fn load_codes(
        codes: Vec<String>,
        account: &UnlockedAccount,
        application: &Application,
        connection: &MyConnection,
    ) -> CommonResult<Vec<ReadScope>> {
        let scopes: Vec<ReadScope> = read_grant_scope::table
            .filter(read_grant_scope::application_id.eq(application.id))
            .filter(read_grant_scope::code.eq(any(codes)))
            .get_results(connection)?;

        for scope in &scopes {
            if !account.verify_record(scope) {
                return Err(CommonError::FailedVerification(Some(
                    "Write scope failed verification.".to_owned(),
                )));
            }
        }

        Ok(scopes)
    }

    pub fn to_unlocked(
        &self,
        account: &UnlockedAccount,
        connection: &MyConnection,
    ) -> CommonResult<UnlockedReadScope> {
        let read_keys = ReadGrantKey::load_with_account(self, account, connection)?;

        Ok(UnlockedReadScope {
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
        diesel::delete(read_grant_scope::table.filter(read_grant_scope::id.eq(self.id)))
            .execute(connection)?;
        Ok(())
    }
}

impl UnlockedReadScope {
    pub fn authorize(
        &self,
        account: &UnlockedAccount,
        client: &Client,
        connection: &MyConnection,
    ) -> CommonResult<()> {
        for read_key in &self.read_keys {
            read_key.authorize(account, client, connection)?;
        }

        Ok(())
    }

    pub fn add_new_key(&self, account: &UnlockedAccount, connection: &MyConnection) -> CommonResult<()> {
        let key = ReadGrantKey::new(self, account);
        key.save(connection)?;
        Ok(())
    }
}

impl Signed for NewReadScope {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[self.application_code.as_bytes(), self.code.as_bytes()])
    }

    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl Signed for ReadScope {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[self.application_code.as_bytes(), self.code.as_bytes()])
    }

    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }
}

impl NewReadScope {
    pub fn save(self, connection: &MyConnection) -> CommonResult<ReadScope> {
        Ok(diesel::insert_into(read_grant_scope::table)
            .values(self)
            .get_result(connection)?)
    }
}

