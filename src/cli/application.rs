use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password};
use model::account::Account;
use model::application::Application;
use model::scope::{WriteScope, ReadScope};

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("application")
        .about("Administration operations for application")
        .subcommand(SubCommand::with_name("add")
            .about("Add a new application")
            .arg(Arg::with_name("username")
               .short("u")
               .long("username")
               .help("The account for which to add an application.")
               .value_name("USERNAME")
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
               .help("The application code.")
               .value_name("CODE")
               .takes_value(true)
            )
            .arg(Arg::with_name("description")
               .short("d")
               .long("description")
               .help("description of the application.")
               .value_name("DESCRIPTION")
               .takes_value(true)
            )
            .arg(Arg::with_name("url")
               .long("url")
               .help("The url of the application server.")
               .value_name("SERVER_URL")
               .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("list").about("Show all applications"))
        .subcommand(SubCommand::with_name("delete")
            .about("Delete application.")
            .arg(Arg::with_name("username")
                 .short("u")
                 .long("username")
                 .help("The account name for which to delete the application.")
                 .value_name("USERNAME")
                 .takes_value(true)
            )
            .arg(Arg::with_name("password")
                 .short("p")
                 .long("password")
                 .help("The account's current password.")
                 .value_name("PASSWORD")
                 .takes_value(true)
            )
            .arg(Arg::with_name("code")
               .short("c")
               .long("code")
               .help("The application code to delete.")
               .value_name("CODE")
               .takes_value(true)
            )
            .arg(Arg::with_name("force")
                 .short("f")
                 .long("force")
                 .help("Delete without confirmation")
            )
        )
        .subcommand(SubCommand::with_name("scope")
            .about("edit scopes.")
            .arg(Arg::with_name("username")
                 .short("u")
                 .long("username")
                 .help("The account name for which to edit application scopes.")
                 .value_name("USERNAME")
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
               .help("The application code to edit.")
               .value_name("CODE")
               .takes_value(true)
            )
            .arg(Arg::with_name("write")
                 .short("w")
                 .long("write")
                 .help("Write scope code, can be used multiple times.")
                 .multiple(true)
            )
            .arg(Arg::with_name("read")
                 .short("r")
                 .long("read")
                 .help("Read scope code, can be used multiple times.")
                 .multiple(true)
            )
            .arg(Arg::with_name("delete")
                 .short("d")
                 .long("delete")
                 .help("Delete the listed scopes")
            )
            .arg(Arg::with_name("force")
                 .short("f")
                 .long("force")
                 .help("Delete without confirmation")
            )
        )
}

pub fn run(matches: &ArgMatches) {

    let connection = establish_connection().unwrap();

    // Create new application.
    if let Some(matches) = matches.subcommand_matches("add") {

        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Account name: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Account password: "),
        };

        let application_code = match matches.value_of("code") {
            Some(code) => code.to_owned(),
            None => get_input("Application code: "),
        };

        let description = match matches.value_of("description") {
            Some(name) => name.to_owned(),
            None => get_input("Description: "),
        };

        let server_url = match matches.value_of("url") {
            Some(url) => url.to_owned(),
            None => get_input("Application server url: "),
        };

        let account = Account::load_unlocked(&username, &password, &connection)
            .expect("Account and password not recognized.");

        let application = Application::new(&application_code, &description, &server_url, &account);

        match application.save(&connection) {
            Ok(_) => println!("Application \"{}\" added successfully.", application_code),
            Err(e) => eprintln!("Could not save application. Error \"{}\"", e),
        }
    }

    // Delete application.
    if let Some(matches) = matches.subcommand_matches("delete") {

        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Account name: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Account password: "),
        };

        let application_code = match matches.value_of("code") {
            Some(code) => code.to_owned(),
            None => get_input("Application code: "),
        };

        if matches.is_present("force") || 
            get_input(&format!("Are you sure you want to delete {}? [y/n]: ", &application_code)) == "y" 
            {

            match Account::load_unlocked(&username, &password, &connection) {
                Ok(account) => {
                    match Application::load_by_code(&application_code, &account, &connection) {
                        Ok(app) => match app.delete(&connection) {
                            Ok(_) => println!("{} application deleted", &application_code),
                            Err(e) => eprintln!("Could not delete {}. Error \"{}\"", &application_code, e),
                        },
                        Err(e) => eprintln!("Could not locate record {}. Error \"{}\"", &application_code, e),
                    };
                },
                Err(_) => eprintln!("Could not find account {}.", &username), 
            }
        }
    }
/*
            .arg(Arg::with_name("write")
                 .short("w")
                 .long("write")
                 .help("Write scope code, can be used multiple times.")
                 .multiple(true)
            )
            .arg(Arg::with_name("read")
                 .short("r")
                 .long("read")
                 .help("Read scope code, can be used multiple times.")
                 .multiple(true)
            )
            .arg(Arg::with_name("delete")
                 .short("d")
                 .long("delete")
                 .help("Delete the listed scopes")
            )
            .arg(Arg::with_name("force")
                 .short("f")
                 .long("force")
                 .help("Delete without confirmation")
            )
*/
    // add remove application scopes
    if let Some(matches) = matches.subcommand_matches("scope") {
        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Account name: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Password: "),
        };

        let application_code = match matches.value_of("code") {
            Some(code) => code.to_owned(),
            None => get_input("Application code: "),
        };

        let write_scope_codes = matches.values_of_lossy("write");
        let read_scope_codes = matches.values_of_lossy("read");

        let account = Account::load_unlocked(
            &username, 
            &password, 
            &connection
            )
            .expect("Could not load account");
        
        let application = Application::load_by_code(
            &application_code, 
            &account, 
            &connection
            )
            .expect("Could not load application");

        if matches.is_present("delete") {
            // Delete named scopes
            if matches.is_present("force") 
                || get_input(
                &format!(
                    "Are you sure you want to delete {}? [y/n]: ", 
                    &application_code
                    )
                ) == "y" 
            {
                // delete write_scopes
                if let Some(scope_codes) = write_scope_codes {
                    let db_scopes = WriteScope::load_codes(scope_codes, &application, &connection).expect("Could not load scopes.");
                    for mut scope in db_scopes {

                        scope.delete(&connection).expect("Could Not delete scope");
                    }
                }
                // delete read_scopes
                if let Some(scope_codes) = read_scope_codes {
                    let db_scopes = ReadScope::load_codes(scope_codes, &application, &connection).expect("Could not load scopes.");
                    for mut scope in db_scopes {

                        scope.delete(&connection).expect("Could Not delete scope");
                    }
                }
            }
        } else {
            // create named write scopes
            if let Some(scope_codes) = write_scope_codes {
                for scope_code in scope_codes {
                   let scope = WriteScope::new(&scope_code, &application, &account); 
                   match scope.save(&connection) {
                       Ok(s) => println!("Write Scope {} created for {} application", s.code, s.application_code),
                       Err(_) => eprintln!("Write Scope {} creation FAILED for {} application", scope_code, application.code),
                   };
                }
            }

            // Create read scopes
            if let Some(scope_codes) = read_scope_codes {
                for scope_code in scope_codes {
                   let scope = WriteScope::new(&scope_code, &application, &account); 
                   match scope.save(&connection) {
                       Ok(s) => println!("Write Scope {} created for {} application", s.code, s.application_code),
                       Err(_) => eprintln!("Write Scope {} creation FAILED for {} application", scope_code, application.code),
                   };
                }
            }
        }
    }

    // list all applications
    if let Some(_) = matches.subcommand_matches("list") {

        let records = Application::load_all(&connection).expect("Error loading all applications.");

        for i in 0..records.len() {
            println!("{} - {}: {}", records[i].account_id, records[i].code, records[i].description);
        }
    }

}

