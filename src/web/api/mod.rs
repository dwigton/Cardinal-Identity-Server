/*
use rocket::form::Form;
use rocket::response::content::Json;
use serde_json::json;
use serde_json::Value;
use serde::Serialize;
use rocket::response::status::Unauthorized;

#[derive(FromForm)]
pub struct AuthorizationParameters {
    grant_type: String,
    username: String,
    password: String,
    scope: String
}

#[derive(Serialize)]
pub struct ClientAccessToken {
    access_token: Vec<u8>,
    token_type: String,
    expires_in: u64,
    refresh_token: Vec<u8>,
}

#[post("/authorize", format = "application/x-www-form-urlencoded", data = "<auth_params>")]
pub fn authorize(auth_params: Form<AuthorizationParameters>) -> Result<Json<String>, Unauthorized<String>> {

    if auth_params.grant_type == "password" {
        Ok(
        Json(
                ClientAccessToken {
                    access_token: b"1234567789".to_vec(),
                    token_type: "bearer".to_string(),
                    expires_in: 300,
                    refresh_token: b"987654321".to_vec(),
                }
            ).to_string()
        )
    } else {
        Unauthorized(String::from("Unrecognized token_type"))
    }
}

#[get("/token")]
pub fn token() ->Json<Value> {
    Json(serde_json::from_str( r#"{ "status": "ok"}"#))
}

#[get("/revoke")]
pub fn revoke() ->Json<Value> {
    Json(serde_json::from_str(r#"{ "status": "ok"}"#))
}
*/

//#[post("/account/add")]
//pub fn add_account() -> Json<JsonValue>
