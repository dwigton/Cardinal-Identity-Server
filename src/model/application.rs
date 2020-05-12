use database::schema::{application, account};
use database::MyConnection;
use diesel::prelude::*;
use diesel::{update, insert_into, result, delete};
use error::{CommonResult, CommonError};
use base64::{encode, decode};
use model::account::UnlockedAccount;

pub struct PortableApplication {
    pub name: String,
    pub server_url: String,
    //pub clients: Vec<PortableClient>,
    //pub read_grant_scopes: Vec<ReadGrantScope>,
    //pub write_grant_scopes: Vec<WriteGrantScope>,
}

#[derive(Insertable)]
#[table_name = "application"]
pub struct NewApplication {
    pub name: String,
    pub account_id: i32,
    pub server_url: String,
}

#[derive(Queryable)]
#[table_name = "application"]
pub struct Application {
    pub id: i32,
    pub name: String,
    pub account_id: i32,
    pub server_url: String,
}

impl NewApplication {
    pub fn new (account: &UnlockedAccount, name: &str, server_url: &str) -> NewApplication {

        NewApplication {
            name: name.to_string(),
            server_url: server_url.to_string(),
            account_id: account.id,
        }
    }

    pub fn from_portable (account: &UnlockedAccount, import: &PortableApplication) -> NewApplication {
        NewApplication::new(account, &import.name, &import.server_url)
    }

    pub fn save (&self, connection: &MyConnection) -> CommonResult<Application> {

        Ok(diesel::insert_into(application::table).values(self).get_result(connection)?)

    }
}

impl Application {
    pub fn to_portable(&self, export_key: &str, connection: &MyConnection) -> PortableApplication {

        PortableApplication {
            name: self.name.clone(),
            server_url: self.server_url.clone(),
        }
    }

}
