use clap::{App, Arg, ArgMatches, SubCommand};
use super::{get_input, get_new_password, get_password};
use crate::database::establish_connection;
use crate::database::MyConnection;
use crate::model::account::Account;
use anyhow::{bail, Context, Result};

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("account")
        .about("Administration operations for accounts")
        .subcommand(
            SubCommand::with_name("add")
                .about("Add a new account")
                .arg(
                    Arg::with_name("username")
                        .short("a")
                        .long("username")
                        .help("The account name for which to create a new account.")
                        .value_name("USERNAME")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("email")
                        .short("e")
                        .long("email")
                        .help("Email address associated with the account.")
                        .value_name("USERNAME")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("password")
                        .short("p")
                        .long("password")
                        .help("The password used to encrypt this account's keys.")
                        .value_name("PASSWORD")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("exportkey")
                        .short("x")
                        .long("exportkey")
                        .help("Required to release an encrypted export of the account's keys.")
                        .value_name("EXPORT_KEY")
                        .takes_value(true),
                ),
        )
        .subcommand(SubCommand::with_name("list").about("Show all accounts"))
        .subcommand(
            SubCommand::with_name("chngpwd")
                .about("Change account password")
                .arg(
                    Arg::with_name("username")
                        .short("a")
                        .long("username")
                        .help("The account name for which to change the password.")
                        .value_name("USERNAME")
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
                    Arg::with_name("newpassword")
                        .short("r")
                        .long("newpassword")
                        .help("The replacement password.")
                        .value_name("NEWPASSWORD")
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("delete")
                .about("Delete account.")
                .arg(
                    Arg::with_name("username")
                        .short("a")
                        .long("username")
                        .help("The account name to delete.")
                        .value_name("USERNAME")
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
        ("chngpwd", Some(m)) => change_password(m, &connection),
        ("delete", Some(m))  => delete(m, &connection),
        ("list", _)          => list(&connection),
        (c, _)               => bail!("Subcommand {} not recognized.", c),
    }
}

fn list(connection: &MyConnection) -> Result<()> {
        let records = Account::load_all(&connection)
            .context("Error loading account accounts.")?;

        for i in 0..records.len() {
            println!("{}", records[i].name);
        }

        Ok(())
}

fn delete(matches: &ArgMatches, connection: &MyConnection) -> Result<()> {

    let username = match matches.value_of("username") {
        Some(u) => u.to_owned(),
        None => get_input("Account name: "),
    };

    let password = match matches.value_of("password") {
        Some(p) => p.to_owned(),
        None => get_password("Password: "),
    };

    if !(matches.is_present("force")
         || get_input(&format!(
                 "Are you sure you want to delete {}? [y/n]: ",
                 &username
                 )) == "y")
    {
        bail!("Password reset cancelled.");
    }

    let name = username.clone();

    Account::load_unlocked(username, password, &connection)
        .context("No such username and password.")?
        .delete(&connection)
        .context(format!("Could not delete {}.", &name))?;

    println!("Account {} deleted", &name);

    Ok(())
}

fn change_password(matches: &ArgMatches, connection: &MyConnection) -> Result<()> {

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

    let name = username.clone();

    let unlocked_account = Account::load_unlocked(username, password, &connection)
        .context("Username and password not recognized.")?;

    unlocked_account.change_password(&new_password, &connection)
        .context("Could not change password.")?;

    println!("Password successfully changed for account {}.", &name);
    
    Ok(())
}

fn add(matches: &ArgMatches, connection: &MyConnection) -> Result<()> {

    let username = match matches.value_of("username") {
        Some(u) => u.to_owned(),
        None => get_input("New account name: "),
    };

    let email = match matches.value_of("email") {
        Some(u) => u.to_owned(),
        None => get_input("Email Address for new account: "),
    };

    let password = match matches.value_of("password") {
        Some(p) => p.to_owned(),
        None => get_new_password("New account password: ", "Reenter password: "),
    };

    let export_key = match matches.value_of("exportkey") {
        Some(p) => p.to_owned(),
        None => get_new_password("New account export key: ", "Reenter export key: "),
    };

    let account = Account::new(&username, &email, &password, &export_key, false);

    account.save(&connection)?;

    println!("New account \"{}\" created successfully.", username);
    
    Ok(())
}
