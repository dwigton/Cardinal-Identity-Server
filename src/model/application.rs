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
    pub fn new (account: &UnlockedAccount, name: &str, server_url: &str) -> CommonResult<NewApplication> {

        Ok(NewApplication {
            name,
            server_url,
            account_id: account.id,
        })
    }


    pub fn save (&self, connection: &MyConnection) -> CommonResult<Application> {

        diesel::insert_into(account::table).values(self).get_result(connection)

    }
}

impl Application {
    pub fn to_portable(&self, export_key: &str, connection: &MyConnection) -> PortableApplication {

        PortableApplication {
            name: self.name,
            server_url: self.server_url,
        }
    }

    pub fn from_portable (account: &UnlockedAccount, import: &PortableApplication) -> CommonResult<Application> {
        let new_application = NewApplication::new(account, import.name, import.server_url);
        new_application.save()
    }
}
