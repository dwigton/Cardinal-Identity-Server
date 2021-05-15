use rocket::request::Form;
use rocket_contrib::json::{Json, JsonValue};

#[derive(FromForm)]
pub struct AuthorizationParameters {
    grant_type: String,
    username: String,
    password: String,
    scope: String
}

#[post("/authorize", format = "application/x-www-form-urlencoded", data = "<auth_params>")]
pub fn authorize(auth_params: Form<AuthorizationParameters>) ->Json<JsonValue> {

    if auth_params.grant_type == "password" {
        Json(json!({ 
            "access_token": "1234567789",
            "token_type": "bearer",
            "expires_in": "300",
            "refresh_token": "987654321"
        }))
    } else {
        Json(json!({ 
            "status": "failed",
            "reason": "grant_type not recognized."
        }))
    }
}

#[get("/token")]
pub fn token() ->Json<JsonValue> {
    Json(json!({ "status": "ok"}))
}

#[get("/revoke")]
pub fn revoke() ->Json<JsonValue> {
    Json(json!({ "status": "ok"}))
}

//#[post("/account/add")]
//pub fn add_account() -> Json<JsonValue>
