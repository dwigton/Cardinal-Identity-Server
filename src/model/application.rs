use database::schema::{application};
use database::MyConnection;
use diesel::prelude::*;
use error::{CommonResult, CommonError};
use model::account::UnlockedAccount;
use encryption::hash_by_parts;
use model::Signable;

pub struct PortableApplication {
    pub code: String,
    pub description: String,
    pub server_url: String,
    //pub clients: Vec<PortableClient>,
    //pub read_grant_scopes: Vec<ReadGrantScope>,
    //pub write_grant_scopes: Vec<WriteGrantScope>,
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
    pub fn save (&self, connection: &MyConnection) -> CommonResult<Application> {

        Ok(diesel::insert_into(application::table).values(self).get_result(connection)?)

    }
}

impl Signable for NewApplication {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
                   self.code.as_bytes(), 
                   self.description.as_bytes(),
                   self.server_url.as_bytes()
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl Signable for Application {
    fn record_hash(&self) -> [u8; 32] {
       hash_by_parts(&[
                   self.code.as_bytes(), 
                   self.description.as_bytes(),
                   self.server_url.as_bytes()
       ])
    }

    fn signature(&self) -> Vec<u8>{
        self.signature.clone()
    }
}

impl Application {
    pub fn new(code: &str, description: &str, server_url: &str, account: &UnlockedAccount) -> NewApplication {
        let mut application = NewApplication {
            code: code.to_string(),
            description: description.to_string(),
            account_id: account.id,
            server_url: server_url.to_string(),
            signature: Vec::new(),
        };

        application.signature = account.sign_record(&application);

        application
    }

    pub fn from_portable (account: &UnlockedAccount, import: &PortableApplication) -> NewApplication {
        Application::new(&import.code, &import.description, &import.server_url, account)
    }

    pub fn to_portable(&self, _export_key: &str, _connection: &MyConnection) -> PortableApplication {

        PortableApplication {
            code: self.code.clone(),
            description: self.description.clone(),
            server_url: self.server_url.clone(),
        }
    }

    pub fn load_by_code ( code: &str, account: &UnlockedAccount, connection: &MyConnection) -> CommonResult<Application> {
        let application = application::table
            .filter( application::code.eq(code))
            .filter( application::account_id.eq(account.id))
            .first(connection)?;

        if account.verify_record(&application) {
            Ok(application)
        } else {
            Err(CommonError::FailedVerification(None))
        }
    }

    pub fn load_all (connection: &MyConnection) -> CommonResult<Vec<Application>> {
        Ok(application::table.load(connection)?)
    }

    pub fn load_all_for_account (account: &UnlockedAccount, connection: &MyConnection) -> CommonResult<Vec<Application>> {
        Ok(
            application::table
            .filter( application::account_id.eq(account.id))
            .get_results(connection)?
          )
    }

    pub fn delete (self, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(application::table.filter(application::id.eq(self.id))).execute(connection)?;
        Ok(())
    }
}
