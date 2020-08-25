extern crate dotenv;
extern crate r2d2;
extern crate r2d2_diesel;

pub mod schema;

use self::dotenv::dotenv;
use self::r2d2_diesel::ConnectionManager;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::ConnectionError;
use std::ops::Deref;

// An alias to the type for a pool of Diesel Postgres connections
pub type MyConnection = PgConnection;
pub type Pool = r2d2::Pool<ConnectionManager<MyConnection>>;

pub struct DbConn(pub r2d2::PooledConnection<ConnectionManager<MyConnection>>);

impl Deref for DbConn {
    type Target = MyConnection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub fn init_pool() -> Pool {
    let database_url =
        dotenv::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");
    let manager = ConnectionManager::<MyConnection>::new(database_url);
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create database connection pool.")
}

pub fn establish_connection() -> Result<MyConnection, ConnectionError> {
    dotenv().ok();

    let database_url =
        dotenv::var("DATABASE_URL").expect("DATABASE_URL environment variable must be set");

    MyConnection::establish(&database_url)
}

pub fn can_connect_to_url(database_url: &str) -> bool {
    MyConnection::establish(&database_url).is_ok()
}
