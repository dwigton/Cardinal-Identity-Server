mod admin;
mod api;
use rocket_dyn_templates::Template;
use rocket::fs::{FileServer, relative};
use rocket::tokio::runtime::Runtime;
use crate::database::{DbConn};
use anyhow::Result;

pub fn run() -> Result<()> {
    let rt = Runtime::new()?;

    rt.block_on(
    rocket::build()
        .attach(DbConn::fairing())
        .mount("/", routes![
               //api::authorize, 
               //api::token, 
               //api::revoke, 
               admin::login,
               admin::post_login, 
               admin::index,
               admin::forbidden_index,
               admin::logout,
               admin::user_logged_in_root,
               admin::not_logged_in_root,
               admin::join_server,
        ])
        .mount("/public", FileServer::from(relative!("/src/web/media")))
        .mount("/css", FileServer::from(relative!("/src/web/css")))
        .attach(Template::fairing())
        .launch())?;

    Ok(())
}

