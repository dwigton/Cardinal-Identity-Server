mod view;

use rocket::response::{Redirect, Flash};
use rocket::request::{self, FromRequest, Form, Request};
use rocket::outcome::Outcome;
use rocket::http::{Cookie, CookieJar};
use rocket_contrib::templates::Template;
use crate::model::account::Account;
use crate::model::application::Application;
use crate::database::DbConn;
use self::view::{AdminContext, LoginContext, ApplicationView};
use base64::encode;

#[derive(FromForm, Clone)]
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
pub async fn login() -> Template {
    let context = LoginContext {
        title: "Login".to_string()
    };
    Template::render("login", &context)
}

#[post("/login", format = "application/x-www-form-urlencoded", data = "<login_params>", rank = 2)]
pub async fn post_login(connection: DbConn, cookies: &CookieJar<'_>, login_params: Form<LoginParameters>) -> Result<Redirect, Flash<Redirect>> {

    let LoginParameters {username, password} = login_params.into_inner();
    let cookie_username = username.clone();
    let cookie_password = password.clone();
   
    let account = connection.run(move |c| Account::load_unlocked(username.clone(), password.clone(), &c)).await;

    match account {
        Ok(_) => {
            cookies.add_private(Cookie::new("username", cookie_username));
            cookies.add_private(Cookie::new("password", cookie_password));
            Ok(Redirect::to("/home"))
        },
        Err(_) => Err(Flash::error(Redirect::to("/login"), "Invalid username/password.")),
    }
}

#[post("/logout")]
pub fn logout(cookies: &CookieJar<'_>) -> Flash<Redirect> {
    cookies.remove_private(Cookie::named("account"));
    Flash::success(Redirect::to("/login"), "Successfully logged out.")
}

#[get("/home")]
pub async fn index(connection: DbConn, user: LoggedInUser) -> Template {

    let LoggedInUser { username: username, password: password} = user;
    let display_user = username.clone();

    let admin_user = 
        connection.run(
            move
            |c| Account::load_unlocked(username, password, c).unwrap()
            ).await;

    let display_key = admin_user.public_key.clone();

    let applications = 
        connection.run(
            move
            |c| Application::load_all_for_account(&admin_user, c).unwrap()
            ).await;

    let view_applications = ApplicationView::from_applications(&applications);

    let context = AdminContext {
        title: "Home".to_string(),
        username: display_user,
        public_key: encode(display_key),
        applications: view_applications,
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
