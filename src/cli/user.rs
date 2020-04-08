use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password, get_new_password};
use model::user::User;

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("user")
        .about("Administration operations for users")
        .subcommand(SubCommand::with_name("add")
            .about("Add a new user account")
            .arg(Arg::with_name("username")
               .short("u")
               .long("username")
               .help("The user name for which to create a new account.")
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
               .help("Required to release an encrypted export of the user's keys.")
               .value_name("EXPORT_KEY")
               .takes_value(true)
            )
        )
        .subcommand(SubCommand::with_name("list").about("Show all users"))
        .subcommand(SubCommand::with_name("chngpwd")
            .about("Change user password")
            .arg(Arg::with_name("username")
                 .short("u")
                 .long("username")
                 .help("The user name for which to change the password.")
                 .value_name("USERNAME")
                 .takes_value(true)
            )
            .arg(Arg::with_name("password")
                 .short("p")
                 .long("password")
                 .help("The user's current password.")
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
            .about("Delete user.")
            .arg(Arg::with_name("username")
                 .short("u")
                 .long("username")
                 .help("The user name for which to change the password.")
                 .value_name("USERNAME")
                 .takes_value(true)
            )
            .arg(Arg::with_name("password")
                 .short("p")
                 .long("password")
                 .help("The user's current password.")
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

    // Create new user.
    if let Some(matches) = matches.subcommand_matches("add") {

        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Username: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_new_password("New user password: ", "Reenter password: "),
        };

        let export_key = match matches.value_of("exportkey") {
            Some(p) => p.to_owned(),
            None => get_new_password("New user export key: ", "Reenter export key: "),
        };

        let mut user = User::new(&username, &password, &export_key);

        match user.save(&connection) {
            Ok(_) => println!("User \"{}\" created successfully.", username),
            Err(e) => eprintln!("Could not save new user. Error \"{}\"", e),
        }

    }

    // Change user password.
    if let Some(matches) = matches.subcommand_matches("chngpwd") {

        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Username: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Current password: "),
        };

        let new_password = match matches.value_of("newpassword") {
            Some(p) => p.to_owned(),
            None => get_new_password("New user password: ", "Reenter new password: "),
        };

        match User::load(&username, &password, &connection) {
            Ok(mut user) => {
                user.change_password(&new_password);
                match user.save(&connection) {
                    Ok(_) => println!("Password successfully changed for user {}.", &username),
                    Err(e) => println!("Could not change password. Error \"{}\"", e),
                }
            }
            Err(_) => println!("Could not find user {}.", &username), 
        }
    }

    // Delete a user.
    if let Some(matches) = matches.subcommand_matches("delete") {
        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Username: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("Password: "),
        };

        if matches.is_present("force") || 
            get_input(&format!("Are you sure you want to delete {}? [y/n]: ", &username)) == "y" 
            {

            match User::load(&username, &password, &connection) {
                Ok(user) => {
                    match user.delete(&connection) {
                        Ok(_) => println!("User {} deleted", &username),
                        Err(e) => println!("Could not delete {}. Error \"{}\"", &username, e),
                    }
                }
                Err(_) => println!("Could not find user {}.", &username), 
            }
        }
    }

    // list all users
    if let Some(_) = matches.subcommand_matches("list") {

        let records = User::load_all(&connection).expect("Error loading user accounts.");

        for i in 0..records.len() {
            println!("{}", records[i].username);
        }
    }
}