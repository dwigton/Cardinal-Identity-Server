#![feature(plugin, decl_macro, custom_derive)]
// #![plugin(rocket_codegen)]

mod admin;
mod api;
use rocket;
use rocket::{Request, State, Outcome};
use rocket::request::{self, FromRequest};
use rocket_contrib::templates::Template;
use rocket_contrib::serve::StaticFiles;
use rocket::http::Status;
use database;
use database::{DbConn, Pool};

impl<'a, 'r> FromRequest<'a, 'r> for DbConn {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<DbConn, ()> {
        let pool = request.guard::<State<Pool>>()?;
        match pool.get() {
            Ok(conn) => Outcome::Success(DbConn(conn)),
            Err(_) => Outcome::Failure((Status::ServiceUnavailable, ()))
        }
    }
}

pub fn run() {
    rocket::ignite()
        .manage(database::init_pool())
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
        .launch();
}
