use crate::model::client::Client;
use crate::model::write_scope::WriteScope;
use crate::database::DbConn;

/// Data to pass to the login screen
#[derive(Serialize)]
pub struct LoginContext {
    title: String,
}

/// data to pass the admin home screen
#[derive(Serialize)]
pub struct AdminContext {
    title: String,
    username: String,
    clients: Vec<Client>,
}

/// data needed to display a client application
#[derive(Serialize)]
pub struct ClientView {
    name: String,
    client_id: String,
    scope: Vec<ScopeView>,
}

/// data needed to display an grant scope.
#[derive(Serialize)]
pub struct ScopeView {
    scope: String,
    write: bool,
}

