use database::schema::{application};
use database::MyConnection;
use diesel::prelude::*;
use diesel::{update, insert_into, result, delete};
use error::CommonResult;
use model::account::UnlockedAccount;

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

impl Application {
    pub fn new(code: &str, description: &str, server_url: &str, account: &UnlockedAccount) -> NewApplication {
        NewApplication {
            code: code.to_string(),
            description: description.to_string(),
            account_id: account.id,
            server_url: server_url.to_string(),
            signature: Vec::new(),
        }
    }

    pub fn from_portable (account: &UnlockedAccount, import: &PortableApplication) -> NewApplication {
        Application::new(&import.code, &import.description, &import.server_url, account)
    }

    pub fn to_portable(&self, export_key: &str, connection: &MyConnection) -> PortableApplication {

        PortableApplication {
            code: self.code.clone(),
            description: self.description.clone(),
            server_url: self.server_url.clone(),
        }
    }

    pub fn load_by_code ( code: &str, account: &UnlockedAccount, connection: &MyConnection) -> CommonResult<Application> {
        Ok(
            application::table
            .filter( application::code.eq(code))
            .filter( application::account_id.eq(account.id))
            .first(connection)?
            )
    }

    pub fn load_all (connection: &MyConnection) -> CommonResult<Vec<Application>> {
        Ok(application::table.load(connection)?)
    }

    pub fn delete (self, connection: &MyConnection) -> CommonResult<()> {
        diesel::delete(application::table.filter(application::id.eq(self.id))).execute(connection)?;
        Ok(())
    }
}
