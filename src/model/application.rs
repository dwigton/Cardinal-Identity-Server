use crate::database::schema::application;
use crate::database::MyConnection;
use diesel::prelude::*;
use crate::encryption::hash_by_parts;
use crate::error::{CommonError, CommonResult};
use crate::model::account::UnlockedAccount;
use crate::model::{Signable, Signed};
use crate::model::client::Client;
use crate::model::write_scope::WriteScope;
use crate::model::read_scope::ReadScope;

pub struct PortableApplication {
    pub code: String,
    pub description: String,
    pub server_url: String,
    //pub clients: Vec<PortableClient>,
    //pub read_grant_scopes: Vec<ReadGrantScope>,
    //pub write_grant_scopes: Vec<WriteGrantScope>,
}

pub struct UnsignedApplication {
    pub account_id: i32,
    pub code: String,
    pub description: String,
    pub server_url: String,
}

#[derive(Insertable)]
#[table_name = "application"]
pub struct NewApplication {
    pub account_id: i32,
    pub code: String,
    pub description: String,
    pub server_url: String,
    pub signature: Vec<u8>,
}

#[derive(Queryable)]
pub struct Application {
    pub id: i32,
    pub account_id: i32,
    pub code: String,
    pub description: String,
    pub server_url: String,
    pub signature: Vec<u8>,
}

impl NewApplication {
    pub fn save(&self, connection: &MyConnection) -> CommonResult<Application> {
        Ok(diesel::insert_into(application::table)
            .values(self)
            .get_result(connection)?)
    }
}

impl Signable<NewApplication> for UnsignedApplication {
    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[
            self.code.as_bytes(),
            self.description.as_bytes(),
            self.server_url.as_bytes(),
        ])
    }

    fn sign(&self, signature: Vec<u8>) -> NewApplication {
        NewApplication {
             account_id: self.account_id,
             code: self.code.clone(),
             description: self.description.clone(),
             server_url: self.server_url.clone(),
             signature,
        }
    }
}

impl Signed for NewApplication {
    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[
            self.code.as_bytes(),
            self.description.as_bytes(),
            self.server_url.as_bytes(),
        ])
    }
}

impl Signed for Application {
    fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    fn record_hash(&self) -> [u8; 32] {
        hash_by_parts(&[
            self.code.as_bytes(),
            self.description.as_bytes(),
            self.server_url.as_bytes(),
        ])
    }
}

impl Application {
    pub fn new(
        code: &str,
        description: &str,
        server_url: &str,
        account: &UnlockedAccount,
    ) -> NewApplication {
        let application = UnsignedApplication {
            code: code.to_string(),
            description: description.to_string(),
            account_id: account.id,
            server_url: server_url.to_string(),
        };

        account.sign_record(&application)
    }

    pub fn from_portable(
        account: &UnlockedAccount,
        import: &PortableApplication,
    ) -> NewApplication {
        Application::new(
            &import.code,
            &import.description,
            &import.server_url,
            account,
        )
    }

    pub fn to_portable(
        &self,
        _export_key: &str,
        _connection: &MyConnection,
    ) -> PortableApplication {
        PortableApplication {
            code: self.code.clone(),
            description: self.description.clone(),
            server_url: self.server_url.clone(),
        }
    }

    pub fn load_by_code(
        code: &str,
        account: &UnlockedAccount,
        connection: &MyConnection,
    ) -> CommonResult<Application> {
        let application = application::table
            .filter(application::code.eq(code))
            .filter(application::account_id.eq(account.id))
            .first(connection)?;

        if account.verify_record(&application) {
            Ok(application)
        } else {
            Err(CommonError::FailedVerification(None))
        }
    }

    pub fn load_all(connection: &MyConnection) -> CommonResult<Vec<Application>> {
        Ok(application::table.load(connection)?)
    }

    pub fn load_all_for_account(
        account: &UnlockedAccount,
        connection: &MyConnection,
    ) -> CommonResult<Vec<Application>> {
        Ok(application::table
            .filter(application::account_id.eq(account.id))
            .get_results(connection)?)
    }

    pub fn delete(self, connection: &MyConnection) -> CommonResult<()> {
        // Delete all dependent clients
        let clients = Client::load_all_for_application(&self, connection)?;

        for client in clients {
            client.delete(connection)?
        }

        // Delete all dependant write grant scopes
        let write_scopes = WriteScope::load_all_for_application(&self, connection)?;

        for write_scope in write_scopes {
            write_scope.delete(connection)?;
        }

        // Delete all dependant read grant scopes.
        let read_scopes = ReadScope::load_all_for_application(&self, connection)?;

        for read_scope in read_scopes {
            read_scope.delete(connection)?;
        }


        diesel::delete(application::table.filter(application::id.eq(self.id)))
            .execute(connection)?;
        Ok(())
    }
}
