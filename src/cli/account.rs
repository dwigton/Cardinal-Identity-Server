use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password, get_new_password};
use model::account::{Account, LockedAccount, UnlockedAccount};

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("account")
        .about("Administration operations for accounts")
        .subcommand(SubCommand::with_name("add")
            .about("Add a new account")
            .arg(Arg::with_name("username")
               .short("u")
               .long("username")
               .help("The account name for which to create a new account.")
               .value_name("USERNAME")
               .takes_value(true)
            )
            .arg(Arg::with_name("password")
               .short("p")
               .long("password")
               .help("The password used to encrypt this account's keys.")
               .value_name("PASSWORD")
               .takes_value(true)
            )
            .arg(Arg::with_name("exportkey")
               .short("x")
               .long("exportkey")
               .help("Required to release an encrypted export of the account's keys.")
               .value_name("EXPORT_KEY")
               .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("list").about("Show all accounts"))
        .subcommand(SubCommand::with_name("chngpwd")
            .about("Change account password")
            .arg(Arg::with_name("username")
                 .short("u")
                 .long("username")
                 .help("The account name for which to change the password.")
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
            .arg(Arg::with_name("newpassword")
                 .short("r")
                 .long("newpassword")
                 .help("The replacement password.")
                 .value_name("NEWPASSWORD")
                 .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("delete")
            .about("Delete account.")
            .arg(Arg::with_name("username")
                 .short("u")
                 .long("username")
                 .help("The account name for which to change the password.")
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
            .arg(Arg::with_name("force")
                 .short("f")
                 .long("force")
                 .help("Delete without confirmation")
            )
        )
}

pub fn run(matches: &ArgMatches) {

    let connection = establish_connection().unwrap();

    // Create new account.
    if let Some(matches) = matches.subcommand_matches("add") {

        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("New account name: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_new_password("New account password: ", "Reenter password: "),
        };

        let export_key = match matches.value_of("exportkey") {
            Some(p) => p.to_owned(),
            None => get_new_password("New account export key: ", "Reenter export key: "),
        };

        let mut account = Account::new(&username, &password, &export_key, false);

        match account.save(&connection) {
            Ok(_) => println!("New account \"{}\" created successfully.", username),
            Err(e) => eprintln!("Could not save new account. Error \"{}\"", e),
        }
    }

    // Change account password.
    if let Some(matches) = matches.subcommand_matches("chngpwd") {

        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Account name: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Current password: "),
        };

        let new_password = match matches.value_of("newpassword") {
            Some(p) => p.to_owned(),
            None => get_new_password("New account password: ", "Reenter new password: "),
        };

        match Account::with_name(&username, &connection) {
            Ok(locked_account) => {

                let mut unlocked_account = locked_account
                    .to_unlocked(&password)
                    .expect("username and password not recognized.");

                match unlocked_account.change_password(&new_password, &connection) {
                    Ok(_) => println!("Password successfully changed for account {}.", &username),
                    Err(e) => eprintln!("Could not change password. Error \"{}\"", e),
                }
            }
            Err(_) => eprintln!("Could not find account {}.", &username), 
        }
    }

    // Delete a account.
    if let Some(matches) = matches.subcommand_matches("delete") {
        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Account name: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Password: "),
        };

        if matches.is_present("force") || 
            get_input(&format!("Are you sure you want to delete {}? [y/n]: ", &username)) == "y" 
            {

            match Account::with_name(&username, &connection) {
                Ok(account) => {
                    // seems like the password should have to be verified
                    // or have an admin account to delete.
                    match account.delete(&connection) {
                        Ok(_) => println!("Account {} deleted", &username),
                        Err(e) => eprintln!("Could not delete {}. Error \"{}\"", &username, e),
                    }
                }
                Err(_) => eprintln!("Could not find account {}.", &username), 
            }
        }
    }

    // list all accounts
    if let Some(_) = matches.subcommand_matches("list") {

        let records = Account::load_all(&connection).expect("Error loading account accounts.");

        for i in 0..records.len() {
            println!("{}", records[i].name);
        }
    }
}
