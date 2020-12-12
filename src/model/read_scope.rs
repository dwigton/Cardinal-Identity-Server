use crate::database::schema::read_grant_scope;
use crate::database::schema::application;
use crate::database::MyConnection;
use diesel::expression::dsl::any;
use diesel::prelude::*;
use crate::error::{CommonError, CommonResult};
use crate::model::account::UnlockedAccount;
use crate::model::application::Application;
use crate::model::{Signable, Signed};
use crate::model::read_authorization::{ReadGrantKey, UnlockedReadGrantKey};
use crate::model::client::Client;
use crate::encryption::hash_by_parts;

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

pub struct NewReadScope {
    pub application_id: i32,
    pub application_code: String,
    pub code: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub signature: Vec<u8>,
}

#[derive(Insertable)]
#[table_name = "read_grant_scope"]
pub struct InsertReadScope {
    pub application_id: i32,
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

impl From<NewReadScope> for InsertReadScope {
    fn from(item: NewReadScope) -> InsertReadScope {
        InsertReadScope {
            application_id: item.application_id,
            code: item.code,
            display_name: item.display_name,
            description: item.description,
            signature: item.signature,
        }
    }
}

impl Signable<NewReadScope> for UnsignedReadScope {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[self.application_code.as_bytes(), self.code.as_bytes()])
    }

    fn sign(&self, signature: Vec<u8>) -> NewReadScope {
        NewReadScope{
            application_id: self.application_id,
            application_code: self.application_code.clone(),
            code: self.code.clone(),
            display_name: self.display_name.clone(),
            description: self.description.clone(),
            signature,
        }
    }
}

impl ReadScope {
    pub fn new(code: &str, application: &Application, account: &UnlockedAccount) -> NewReadScope {
        let scope = UnsignedReadScope {
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
            .inner_join(application::table)
            .filter(read_grant_scope::application_id.eq(application.id))
            .filter(read_grant_scope::code.eq(any(codes)))
            .select((
                    read_grant_scope::id,
                    read_grant_scope::application_id,
                    application::code,
                    read_grant_scope::code,
                    read_grant_scope::display_name,
                    read_grant_scope::description,
                    read_grant_scope::signature,
                    ))
            .load::<ReadScope>(connection)?;

        for scope in &scopes {
            if !account.verify_record(scope) {
                return Err(CommonError::FailedVerification(Some(
                    "Read scope failed verification.".to_owned(),
                )));
            }
        }

        Ok(scopes)
    }

    pub fn load_all_for_application(application: &Application, connection: &MyConnection) -> CommonResult<Vec<ReadScope>> {

        Ok(read_grant_scope::table
            .inner_join(application::table)
            .filter(read_grant_scope::application_id.eq(application.id))
            .select((
                    read_grant_scope::id,
                    read_grant_scope::application_id,
                    application::code,
                    read_grant_scope::code,
                    read_grant_scope::display_name,
                    read_grant_scope::description,
                    read_grant_scope::signature,
                    ))
            .load::<ReadScope>(connection)?)
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

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        //delete dependant scope keys
        
        let keys = ReadGrantKey::load_all_for_scope(&self, connection)?;

        for key in keys {
            key.delete(connection)?;
        }

        diesel::delete(read_grant_scope::table.filter(read_grant_scope::id.eq(self.id)))
            .execute(connection)?;
        Ok(())
    }

    pub fn load_id(
        id: i32,
        connection: &MyConnection,
    ) -> CommonResult<ReadScope> {
        Ok(read_grant_scope::table
            .inner_join(application::table)
            .filter(read_grant_scope::id.eq(id))
            .select((
                    read_grant_scope::id,
                    read_grant_scope::application_id,
                    application::code,
                    read_grant_scope::code,
                    read_grant_scope::display_name,
                    read_grant_scope::description,
                    read_grant_scope::signature,
                    ))
            .get_result(connection)?)
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

    pub fn revoke(&self, client: &Client, connection: &MyConnection) -> CommonResult<()> {
        for read_key in &self.read_keys {
            read_key.revoke(client, connection)?;
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
        let scope_id = diesel::insert_into(read_grant_scope::table)
            .values(InsertReadScope::from(self))
            .returning(read_grant_scope::id)
            .get_result(connection)?;

        Ok(ReadScope::load_id(scope_id, connection)?)
    }
}

