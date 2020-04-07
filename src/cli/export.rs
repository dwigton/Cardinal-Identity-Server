use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password, get_new_password};
use model::user::User;
use serde_json;
use std::fs;

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("export")
     .about("Exports key files.")
     .arg(Arg::with_name("output")
          .short("o")
          .long("output")
          .help("Sets the output file to create")
          .value_name("FILENAME")
          .takes_value(true)
          )
      .arg(Arg::with_name("username")
           .short("u")
           .long("username")
           .help("The user name to export.")
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
      .arg(Arg::with_name("passphrase")
           .short("P")
           .long("passphrase")
           .help("Used to encrypt the keyfile.")
           .value_name("PASSPHRASE")
           .takes_value(true)
          )
}

pub fn run(matches: &ArgMatches) {

    let username = match matches.value_of("username") {
        Some(u) => u.to_owned(),
        None => get_input("Username: "),
    };

    let password = match matches.value_of("password") {
        Some(p) => p.to_owned(),
        None => get_password(
            &format!("Enter password for {}: ", &username)
            ),
    };

    let export_key = match matches.value_of("exportkey") {
        Some(p) => p.to_owned(),
        None => get_password(
            &format!("Enter export key for {}: ", &username)
            ),
    };

    let passphrase = match matches.value_of("passphrase") {
        Some(p) => p.to_owned(),
        None => get_new_password(
            "Passphrase with which to encrypt keyfile: ",
            "Reenter encryption passphrase: "
            ),
    };

    let connection = establish_connection().unwrap();

    let user = User::load(&username, &password, &connection);

    let user = match user {
        Ok(u) => u,
        Err(_) => panic!("User does not exist"),
    };

    match user.encode_key(&export_key, &passphrase){
        Ok(k) => {
            let output = serde_json::to_string(&k).expect("Key encoded improperly.");
            match matches.value_of("output") {
                Some(f) => {
                    fs::write(&f, output).expect("Could not write data to file.");
                },
                None => println!("{}", &output), 
            }
        },
        Err(_) => eprintln!("Release key invalid."),
    };
}
