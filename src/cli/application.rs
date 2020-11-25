use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password};
use database::establish_connection;
use database::MyConnection;
use model::account::Account;
use model::application::Application;
use model::write_scope::WriteScope;
use model::read_scope::ReadScope;
use anyhow::{bail, Context, Result};

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("application")
        .about("Administration operations for application")
        .subcommand(
            SubCommand::with_name("add")
                .about("Add a new application")
                .arg(
                    Arg::with_name("account_name")
                        .short("u")
                        .long("account_name")
                        .help("The account for which to add an application.")
                        .value_name("ACCOUNT")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("p")
                        .long("password")
                        .help("The account password.")
                        .value_name("PASSWORD")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("code")
                        .short("c")
                        .long("code")
                        .help("The application code.")
                        .value_name("CODE")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("description")
                        .short("d")
                        .long("description")
                        .help("description of the application.")
                        .value_name("DESCRIPTION")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("url")
                        .long("url")
                        .help("The url of the application server.")
                        .value_name("SERVER_URL")
                        .takes_value(true),
                ),
        )
        .subcommand(SubCommand::with_name("list").about("Show all applications"))
        .subcommand(
            SubCommand::with_name("delete")
                .about("Delete application.")
                .arg(
                    Arg::with_name("account_name")
                        .short("u")
                        .long("account_name")
                        .help("The account name for which to delete the application.")
                        .value_name("ACCOUNT")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("p")
                        .long("password")
                        .help("The account's current password.")
                        .value_name("PASSWORD")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("code")
                        .short("c")
                        .long("code")
                        .help("The application code to delete.")
                        .value_name("CODE")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("force")
                        .short("f")
                        .long("force")
                        .help("Delete without confirmation"),
                ),
        )
        .subcommand(
            SubCommand::with_name("scope")
                .about("edit scopes.")
                .arg(
                    Arg::with_name("account_name")
                        .short("u")
                        .long("account_name")
                        .help("The account name for which to edit application scopes.")
                        .value_name("ACCOUNT")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("p")
                        .long("password")
                        .help("The account password.")
                        .value_name("PASSWORD")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("code")
                        .short("c")
                        .long("code")
                        .help("The application code to edit.")
                        .value_name("CODE")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("write")
                        .short("w")
                        .long("write")
                        .help("Write scope code, can be used multiple times.")
                        .multiple(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("read")
                        .short("r")
                        .long("read")
                        .help("Read scope code, can be used multiple times.")
                        .multiple(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("delete")
                        .short("d")
                        .long("delete")
                        .help("Delete the listed scopes"),
                )
                .arg(
                    Arg::with_name("force")
                        .short("f")
                        .long("force")
                        .help("Delete without confirmation"),
                ),
        )
}

pub fn run(matches: &ArgMatches) -> Result<()> {
    let connection = establish_connection()?;

    match matches.subcommand() {
        ("add", Some(m))     => add(m, &connection),
        ("scope", Some(m))   => scope(m, &connection),
        ("delete", Some(m))  => delete(m, &connection),
        ("list", _)          => list(&connection),
        (c, _)               => bail!("Subcommand {} not recognized.", c),
    }
}

fn list(connection: &MyConnection) -> Result<()> {
    let records = Application::load_all(&connection)
        .context("Error loading all applications.")?;

    for i in 0..records.len() {
        println!(
            "{} - {}: {}",
            records[i].account_id, records[i].code, records[i].description
            );
    }

    Ok(())
}

fn scope(matches: &ArgMatches, connection: &MyConnection) -> Result<()> {

    let account_name = match matches.value_of("account_name") {
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

    let account = Account::load_unlocked(&account_name, &password, &connection)
        .expect("Could not load account");

    let application = Application::load_by_code(&application_code, &account, &connection)
        .expect("Could not load application");

    if matches.is_present("delete") {
        // Delete named scopes
        if !(matches.is_present("force")
             || get_input(&format!(
                     "Are you sure you want to delete {}? [y/n]: ",
                     &application_code
                     )) == "y")
        {
            bail!("Scope delete cancelled.");
        }

        // delete write_scopes
        if let Some(scope_codes) = write_scope_codes {
            let db_scopes = WriteScope::load_codes(scope_codes, &application, &connection)
                .context("Could not load scopes.")?;
            for mut scope in db_scopes {
                scope.delete(&connection).context(format!("Could not delete scope {}", scope.code))?;
                println!("Write scope {} deleted successfully.", scope.code);
            }
        }

        // delete read_scopes
        if let Some(scope_codes) = read_scope_codes {
            let db_scopes = ReadScope::load_codes(scope_codes, &account, &application, &connection)
                .context("Could not load scopes.")?;
            for mut scope in db_scopes {
                scope.delete(&connection).context(format!("Could not delete scope {}", scope.code))?;
                println!("Read scope {} deleted successfully.", scope.code);
            }
        }
    } else {
        // create named write scopes
        if let Some(scope_codes) = write_scope_codes {
            for scope_code in scope_codes {
                let scope = WriteScope::new(&scope_code, &application, &account);
                match scope.save(&connection) {
                    Ok(s) => println!(
                        "Write Scope {} created for {} application",
                        s.code, s.application_code
                        ),
                    Err(_) => bail!(
                        "Write Scope {} creation FAILED for {} application",
                        scope_code, application.code
                        ),
                };
            }
        }

        // Create read scopes
        if let Some(scope_codes) = read_scope_codes {
            for scope_code in scope_codes {
                let scope = WriteScope::new(&scope_code, &application, &account);
                match scope.save(&connection) {
                    Ok(s) => println!(
                        "Read Scope {} created for {} application",
                        s.code, s.application_code
                        ),
                    Err(_) => bail!(
                        "Read Scope {} creation FAILED for {} application",
                        scope_code, application.code
                        ),
                };
            }
        }

    }

    Ok(())
}

fn delete(matches: &ArgMatches, connection: &MyConnection) -> Result<()> {
    let account_name = match matches.value_of("account_name") {
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

    if !(matches.is_present("force")
         || get_input(&format!(
                 "Are you sure you want to delete {}? [y/n]: ",
                 &application_code
                 )) == "y")
    {
        bail!("Password reset cancelled.");
    }

    let account = Account::load_unlocked(&account_name, &password, &connection)
        .context("No such username and password.")?;

    Application::load_by_code(&application_code, &account, &connection)
        .context(format!("Could not locate record {}.", &application_code))?
        .delete(&connection)
        .context(format!("Could not delete {}.", &application_code))?;

    println!("Application {} deleted successfully.", &application_code);

    Ok(())
}

fn add(matches: &ArgMatches, connection: &MyConnection) -> Result<()> {
    let account_name = match matches.value_of("account_name") {
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

    let account = Account::load_unlocked(&account_name, &password, &connection)
        .expect("Account and password not recognized.");

    let application = Application::new(&application_code, &description, &server_url, &account);

    match application.save(&connection) {
        Ok(_) => println!("Application \"{}\" added successfully.", application_code),
        Err(_) => bail!("Could not save application."),
    }

    Ok(())
}
