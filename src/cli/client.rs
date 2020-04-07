use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password};
use model::user::User;
use model::client::ClientApp;
use model::write_grant_scope::WriteGrantScope;
use model::read_grant_scope::ReadGrantScope;

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("client")
        .about("create and revoke client authorizations")
        .subcommand(SubCommand::with_name("add")
            .about("Add a new client application authorization.")
            .arg(Arg::with_name("username")
               .short("u")
               .long("username")
               .help("The user for which to create a new client application authorization.")
               .value_name("USERNAME")
               .takes_value(true)
            )
            .arg(Arg::with_name("password")
               .short("p")
               .long("password")
               .help("The user's password.")
               .value_name("PASSWORD")
               .takes_value(true)
            )
            .arg(Arg::with_name("name")
               .short("n")
               .long("name")
               .help("Client Application name.")
               .value_name("NAME")
               .takes_value(true)
            )
            .arg(Arg::with_name("write_scope")
               .short("w")
               .long("write_scope")
               .help("write scope for client authoriztion permission, can be used multiple times to create a multiscope authorization.")
               .multiple(true)
               .value_name("WRITESCOPE")
               .takes_value(true)
            )
            .arg(Arg::with_name("read_scope")
               .short("r")
               .long("read_scope")
               .help("read scope for client authoriztion permission, can be used multiple times to create a multiscope authorization.")
               .multiple(true)
               .value_name("READSCOPE")
               .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("list").about("Show all client authorizations"))
        .subcommand(SubCommand::with_name("revoke")
            .about("Revoke client application authorization.")
            .arg(Arg::with_name("username")
                 .short("u")
                 .long("username")
                 .help("The owner of the client authoriztion")
                 .value_name("USERNAME")
                 .takes_value(true)
            )
            .arg(Arg::with_name("password")
                 .short("p")
                 .long("password")
                 .help("The user's password.")
                 .value_name("PASSWORD")
                 .takes_value(true)
            )
            .arg(Arg::with_name("name")
               .short("n")
               .long("name")
               .help("Client Application name.")
               .value_name("NAME")
               .takes_value(true)
            )
            .arg(Arg::with_name("force")
                 .short("f")
                 .long("force")
                 .help("Revoke without confirmation")
            )
            .arg(Arg::with_name("all")
                 .short("a")
                 .long("all")
                 .help("revoke all authorizations")
            )
            .arg(Arg::with_name("delete")
                 .short("d")
                 .long("delete")
                 .help("Delete client entirely.")
            )
            .arg(Arg::with_name("write_scope")
               .short("w")
               .long("write_scope")
               .help("write scope revoke. Can be used multiple times.")
               .multiple(true)
               .value_name("WRITESCOPE")
               .takes_value(true)
            )
            .arg(Arg::with_name("read_scope")
               .short("r")
               .long("read_scope")
               .help("read scope to revoke, can be used multiple times.")
               .multiple(true)
               .value_name("READSCOPE")
               .takes_value(true)
            )
        )
}

pub fn run(matches: &ArgMatches) {

    let connection = establish_connection().unwrap();

    // Create new client.
    // Returns client Id and client secret.
    if let Some(matches) = matches.subcommand_matches("add") {

        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Username: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("User password: "),
        };

        let client_name = match matches.value_of("name") {
            Some(p) => p.to_owned(),
            None => get_input("New client name: "),
        };

        // multiple scopes allowed. 
        let write_scope_codes = match matches.values_of("write_scope") {
            Some(p) => p.to_owned().collect(),
            None => vec!(),
        };

        let read_scope_codes = match matches.values_of("read_scope") {
            Some(p) => p.to_owned().collect(),
            None => vec!(),
        };

        // load user
        let user = User::load(&username, &password, &connection).expect("Username, password not recognized");

        // Create new client application
        // Should be impossible to trigger a panic on the unwrap.
        let mut client = ClientApp::try_load(
            user.account.as_ref().unwrap().id, 
            &client_name, 
            &connection)
            .expect("Could not load or create client.");

        // Load or create all requested scopes
        let write_scopes = WriteGrantScope::try_load_all(
            &user, 
            &write_scope_codes, 
            &connection
            ).expect("Could not load or create requested scopes.");

        let read_scopes = ReadGrantScope::try_load_all(
            &user, 
            &read_scope_codes, 
            &connection
            ).expect("Could not load or create requested scopes.");

        for write_scope in write_scopes {
            write_scope.authorize(&client, &user, &connection).expect("Could not authorize write scope for client");
        }

        for read_scope in read_scopes {
            read_scope.authorize(&client, &user, &connection).expect("Could not authorize read scope for client");
        }

        println!("{}", client.to_string());
    }

    // Revoke authorization
    if let Some(matches) = matches.subcommand_matches("revoke") {
        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Username: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Password: "),
        };

        let client_name = match matches.value_of("name") {
            Some(p) => p.to_owned(),
            None => get_input("New client name: "),
        };


        if matches.is_present("force") || 
            get_input(&format!("Are you sure you want to delete {}? [y/n]: ", &client_name)) == "y" 
            {
                // load user
                let user = User::load(&username, &password, &connection).expect("Username, password not recognized");

                // multiple scopes allowed. 
                let write_scope_codes = match matches.values_of("write_scope") {
                    Some(p) => p.to_owned().collect(),
                    None => vec!(),
                };

                let read_scope_codes = match matches.values_of("read_scope") {
                    Some(p) => p.to_owned().collect(),
                    None => vec!(),
                };

                let should_delete = matches.values_of("delete").is_some();

                let revoke_all = matches.values_of("all").is_some() || should_delete;

                // Load client application
                // Should be impossible to trigger a panic on the unwrap.
                let client = ClientApp::load_by_name(
                    user.account.as_ref().unwrap().id, 
                    &client_name, 
                    &connection)
                    .expect("Client does not exist.");

                // Load all requested scopes
                let write_scopes = WriteGrantScope::load_all(
                    &user, 
                    &connection
                    ).expect("Could not load write scopes.");

                let read_scopes = ReadGrantScope::load_all(
                    &user, 
                    &connection
                    ).expect("Could not load read scopes.");

                // revoke write authorizations
                for write_scope in write_scopes {

                    let mut should_revoke = revoke_all; 

                    if !should_revoke {
                        for write_scope_code in &write_scope_codes {
                            if write_scope_code == &write_scope.get_code() {
                                should_revoke = true;
                            }
                        }
                    }

                    if should_revoke {
                        write_scope.revoke(&client, &connection).expect("Could not revoke write scope access for client");
                    }
                }

                // Revoke read authorizations
                for read_scope in read_scopes {
                    let mut should_revoke = revoke_all; 

                    if !should_revoke {
                        for read_scope_code in &read_scope_codes {
                            if read_scope_code == &read_scope.get_code() {
                                should_revoke = true;
                            }
                        }
                    }

                    if should_revoke {
                        read_scope.revoke(&client, &connection).expect("Could not revoke read scope access for client");
                    }
                }

                if should_delete {
                    client.delete(&connection).expect("Could not delete client application");
                }
            }
    }
}

