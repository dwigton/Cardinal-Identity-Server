use model::client::ClientApp;
use model::scope::Scope;
use database::DbConn;

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
    clients: Vec<ClientView>,
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

impl ClientView {
    pub fn from_client_applications(clients: &[ClientApp], connection: &DbConn) {
        let mut result = Vec::new();
        for client in clients {
            let grant_scopes = 
            result::push(
                ClientView {

                    name: client.
                }
                );
        }
    }
