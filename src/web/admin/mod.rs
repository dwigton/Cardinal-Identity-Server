mod view;

use rocket::response::{Redirect, Flash};
use rocket::request::{self, FromRequest, Form, Request};
use rocket::outcome::Outcome;
use rocket::http::{Cookie, CookieJar};
use rocket_contrib::templates::Template;
use crate::model::account::Account;
use crate::model::client::Client;
use crate::database::DbConn;
use self::view::{LoginContext, AdminContext, ClientView};

#[derive(FromForm)]
pub struct LoginParameters {
    username: String,
    password: String,
}

pub struct LoggedInUser {
    username: String,
    password: String,
}

pub struct LoggedInAdmin {
    username: String,
    password: String,
}

#[rocket::async_trait]
impl<'a, 'r> FromRequest<'a, 'r> for LoggedInUser {
    type Error = ();

    async fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {

        let username: String = match request.cookies().get_private("username") {
            Some(c) => c.value().to_owned(),
            None => return Outcome::Forward(()),
        };
         
        let password: String = match request.cookies().get_private("password") {
            Some(c) => c.value().to_owned(),
            None => return Outcome::Forward(()),
        };

        Outcome::Success(LoggedInUser{
            username,
            password,
        })
    }
}

#[rocket::async_trait]
impl<'a, 'r> FromRequest<'a, 'r> for LoggedInAdmin {
    type Error = ();

    async fn from_request(request: &'a Request<'r>) -> request::Outcome<Self, Self::Error> {

        let username: String = match request.cookies().get_private("adminname") {
            Some(c) => c.value().to_owned(),
            None => return Outcome::Forward(()),
        };
         
        let password: String = match request.cookies().get_private("password") {
            Some(c) => c.value().to_owned(),
            None => return Outcome::Forward(()),
        };

        Outcome::Success(LoggedInAdmin{
            username,
            password,
        })
    }
}

#[get("/login")]
pub fn login() -> Template {
    let context = LoginContext {
        title: "Login".to_string()
    };
    Template::render("login", &context)
}

#[post("/login", format = "application/x-www-form-urlencoded", data = "<login_params>", rank = 2)]
pub fn post_login(connection: DbConn, mut cookies: &CookieJar<'_>, login_params: Form<LoginParameters>) -> Result<Redirect, Flash<Redirect>> {
    let username = &login_params.username;
    let password = &login_params.password;

    let account = Account::load_unlocked(&username, &password, &connection);

    match account {
        Ok(u) => {
            match u.account {
                Some(_) => {
                    cookies.add_private(Cookie::new("username", username.to_string()));
                    cookies.add_private(Cookie::new("password", password.to_string()));
                    Ok(Redirect::to("/home"))
                },
                None    => Err(Flash::error(Redirect::to("/login"), "Invalid username/password."))
            }
        },
        Err(_) => Err(Flash::error(Redirect::to("/login"), "Invalid username/password.")),
    }
}

#[post("/logout")]
pub fn logout(mut cookies: &CookieJar<'_>) -> Flash<Redirect> {
    cookies.remove_private(Cookie::named("username"));
    cookies.remove_private(Cookie::named("password"));
    Flash::success(Redirect::to("/login"), "Successfully logged out.")
}

#[get("/home")]
pub fn index(connection: DbConn, user: LoggedInUser) -> Template {

    let admin_user = Account::load_unlocked(&user.username, &user.password, &connection).unwrap();
    let clients = Client::load_by_user(&admin_user, &connection).unwrap();
    let view_clients = ClientView::from_client_applications(&clients);
    let context = AdminContext {
        title: "Home".to_string(),
        username: admin_user.username.to_owned(),
    };
    Template::render("home", &context)
}

#[get("/", rank = 2)]
pub fn not_logged_in_root() -> Redirect {
    Redirect::to("/login")
}

#[get("/")]
pub fn user_logged_in_root(_user: LoggedInUser) -> Redirect {
    Redirect::to("/home")
}

#[get("/home", rank = 2)]
pub fn forbidden_index() -> Redirect {
    Redirect::to("/login")
}
