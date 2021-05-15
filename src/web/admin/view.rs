use crate::model::client::Client;
use crate::model::application::Application;

/// Data to pass join application page
#[derive(Serialize)]
pub struct joinContext {
    pub username: String,
    pub application: String,
    pub application_server: String,
}

/// Data to pass to the login screen
#[derive(Serialize)]
pub struct LoginContext {
    pub title: String,
}

/// data to pass the admin home screen
#[derive(Serialize)]
pub struct AdminContext {
    pub title: String,
    pub username: String,
    pub public_key: String,
    pub applications: Vec<ApplicationView>,
}

/// data needed to display a client application
#[derive(Serialize)]
pub struct ClientView {
    pub name: String,
    pub client_id: String,
    pub scope: Vec<ScopeView>,
}

/// data needed to display an grant scope.
#[derive(Serialize)]
pub struct ScopeView {
    pub scope: String,
    pub write: bool,
}

#[derive(Serialize)]
pub struct ApplicationView {
    pub name: String,
}

impl ApplicationView {
    pub fn from_applications(applications: &[Application]) -> Vec<ApplicationView> {
        let mut application_views = Vec::new();

        for application in applications {
            application_views.push(
                ApplicationView{
                    name: application.code.clone(),
                }
                );
        }

        application_views
    }
}
