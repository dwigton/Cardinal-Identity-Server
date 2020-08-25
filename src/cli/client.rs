use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password};
use model::account::Account;
use model::application::Application;
use model::client::{Client};
use model::scope::{WriteScope, ReadScope};
use base64::encode;

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("client")
        .about("create and revoke client authorizations")
        .subcommand(SubCommand::with_name("add")
            .about("Add a new client application authorization.")
            .arg(Arg::with_name("account")
               .short("a")
               .long("account")
               .help("The account for which to create a new client application authorization.")
               .value_name("ACCOUNT")
               .takes_value(true)
            )
            .arg(Arg::with_name("password")
               .short("p")
               .long("password")
               .help("The account's password.")
               .value_name("PASSWORD")
               .takes_value(true)
            )
            .arg(Arg::with_name("code")
               .short("c")
               .long("code")
               .help("Application Code.")
               .value_name("CODE")
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
            .arg(Arg::with_name("account")
                 .short("a")
                 .long("account")
                 .help("The owner of the client authoriztion")
                 .value_name("ACCOUNT")
                 .takes_value(true)
            )
            .arg(Arg::with_name("password")
                 .short("p")
                 .long("password")
                 .help("The account password.")
                 .value_name("PASSWORD")
                 .takes_value(true)
            )
            .arg(Arg::with_name("code")
               .short("c")
               .long("code")
               .help("Application Code.")
               .value_name("CODE")
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

        let account = match matches.value_of("account") {
            Some(a) => a.to_owned(),
            None => get_input("Account name: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Account password: "),
        };

        let application_code = match matches.value_of("code") {
            Some(c) => c.to_owned(),
            None => get_input("Application code: "),
        };

        // multiple scopes allowed. 
        let write_scope_codes = matches.values_of_lossy("write");
        let read_scope_codes = matches.values_of_lossy("read"); 
        // load account
        let account = Account::load_unlocked(&account, &password, &connection)
            .expect("Account and password not recognized.");

        // load application
        let application = Application::load_by_code(&application_code, &account, &connection)
            .expect("Application not found");

        // create new client
        let (token, new_client) = Client::new(&account, &application);

        let client = match new_client.save(&connection) {
            Ok(c) => {
                println!("Client {} for \"{}\" added.", encode(&c.client_id), application_code);
                c
            },
            Err(e) => panic!("Could not save application. Error \"{}\"", e),
        };

        // Create any requested write scope authorizations
        if let Some(values) = write_scope_codes {
            let write_scopes = WriteScope::load_unlocked(&values, &account, &application, &connection)
                .expect("Could not load write scopes."); 

            for write_scope in write_scopes {
                write_scope.authorize(&account, &client, &connection).expect("Could not authorize");
            }
        }

        // Create any requested read scope authorizations
        if let Some(values) = read_scope_codes {
            let locked_read_scopes = ReadScope::load_codes(values, &account, &application, &connection)
                .expect("Could not load read scopes."); 

            for locked_read_scope in locked_read_scopes {
                let read_scope = locked_read_scope.to_unlocked(&account, &connection).expect("Could not unlock read scope");
                read_scope.authorize(&account, &client, &connection).expect("Could not authorize");
            }
        }
    }
}

