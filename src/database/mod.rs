extern crate dotenv;
extern crate r2d2_diesel;
extern crate r2d2;

pub mod schema;
pub mod auth_account;
pub mod admin_auth_account;
pub mod auth_key;
pub mod grant_scope;
pub mod client;
pub mod identity_key;
pub mod scope_authorization;

use diesel::prelude::*;
use diesel::ConnectionError;
use diesel::pg::PgConnection;
use self::r2d2_diesel::ConnectionManager;
use self::dotenv::dotenv;
use std::ops::Deref;

// An alias to the type for a pool of Diesel Postgres connections
pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub struct DbConn(pub r2d2::PooledConnection<ConnectionManager<PgConnection>>);

impl Deref for DbConn {
    type Target = PgConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn init_pool() -> Pool {
    let database_url = dotenv::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder().build(manager).expect("Failed to create database connection pool.")
}

pub fn establish_connection() -> Result<PgConnection, ConnectionError> {
    dotenv().ok();

    let database_url = dotenv::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");

    PgConnection::establish(&database_url)
}

pub fn can_connect_to_url(database_url: &str) -> bool {
    PgConnection::establish(&database_url).is_ok()
}