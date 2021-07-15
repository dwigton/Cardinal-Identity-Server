pub mod schema;

use dotenv::dotenv;
use diesel::pg::PgConnection;
use diesel::ConnectionError;
use anyhow::Result;

use rocket_sync_db_pools::diesel;

use self::diesel::prelude::*;

// An alias to the type for a pool of Diesel Postgres connections
pub type MyConnection = PgConnection;

#[database("diesel")]
pub struct DbConn(MyConnection);

pub fn establish_connection() -> Result<MyConnection, ConnectionError> {
    dotenv().ok();

    let database_url =
        dotenv::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");

    MyConnection::establish(&database_url)
}

pub fn can_connect_to_url(database_url: &str) -> bool {
    MyConnection::establish(&database_url).is_ok()
}
