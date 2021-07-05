mod view;

use rocket::response::{Redirect, Flash};
use rocket::request::{self, FromRequest, Form, Request};
use rocket::outcome::Outcome;
use rocket::http::{Cookie, CookieJar};
use rocket::form::Form;
use rocket_contrib::templates::Template;
use crate::model::account::Account;
use crate::model::application::Application;
use crate::database::DbConn;
use self::view::{JoinContext, AdminContext, LoginContext, ApplicationView};
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

#[derive(FromForm, Clone)]
pub struct NewAccountParameters {
    application: String,
    application_server: String,
    return_url: String,
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

/*
// TODO check api_key to allow account creation.
#[rocket::async_trait]
impl<'a, 'r> FromRequest<'a, 'r> for NewAccountParameters{
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

        Outcome::Success(NewAccountParameters{
            application: String,
            application_server: String,
            return_url: String,
        })
    }
}
*/

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

    let LoggedInUser { username, password} = user;
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

#[get("/join?<application_server>&<application>&<return_url>")]
pub fn join_server(connection: DbConn, cookies: &CookieJar<'_>, application_server: &str, application: &str, return_url: &str) -> Template {
    //let NewAccountParameters {application, application_server, return_url} = request_parameters.into_inner();
    let cookie_application        = application.clone();
    let cookie_application_server = application_server.clone();
    let cookie_return_url         = return_url.clone();

            cookies.add_private(Cookie::new("application", cookie_application));
            cookies.add_private(Cookie::new("application_server", cookie_application_server));
            cookies.add_private(Cookie::new("return_url", cookie_return_url));

    let context = JoinContext {
        application: "headline".to_string(),
        application_server: "http://127.0.0.1:8080".to_string(),
    };

    Template::render("join", &context)
}
