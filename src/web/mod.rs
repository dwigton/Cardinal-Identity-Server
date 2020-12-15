mod admin;
mod api;
use rocket::{Request, State};
use rocket::outcome::Outcome;
use rocket::request::{self, FromRequest};
use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;
use rocket::http::Status;
use rocket::tokio::runtime::Runtime;
use rocket::tokio::prelude::*;
use crate::database::{DbConn};
use anyhow::{bail, Result};

pub fn run() -> Result<()> {
    let mut rt = Runtime::new()?;

    rt.block_on(
    rocket::ignite()
        .attach(DbConn::fairing())
        .mount("/", routes![
               api::authorize, 
               api::token, 
               api::revoke, 
               admin::login,
               admin::post_login, 
               admin::index,
               admin::forbidden_index,
               admin::logout,
               admin::user_logged_in_root,
               admin::not_logged_in_root,
        ])
        .mount("/public", StaticFiles::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/web/media")))
        .mount("/css", StaticFiles::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/web/css")))
        .attach(Template::fairing())
        .launch());

    Ok(())
}

