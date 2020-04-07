use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password, get_new_password};
use model::user::User;
use model::exported_key::ExportedKey;
use serde_json;
use std::fs;
use std::io::{self, Read};

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("import")
     .about("Import key files.")
     .arg(Arg::with_name("file")
          .short("f")
          .long("file")
          .help("Sets the file to import")
          .value_name("FILENAME")
          .takes_value(true)
          )
      .arg(Arg::with_name("username")
           .short("u")
           .long("username")
           .help("The user name to import.")
           .value_name("USERNAME")
           .takes_value(true)
      )
      .arg(Arg::with_name("password")
           .short("p")
           .long("password")
           .help("The user's new password.")
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
      .arg(Arg::with_name("passphrase")
           .short("P")
           .long("passphrase")
           .help("Used to decrypt the keyfile.")
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
        None => get_new_password(
            &format!("Enter new password for {}: ", &username),
            "Reenter new password: "
            ),
    };

    let export_key = match matches.value_of("exportkey") {
        Some(p) => p.to_owned(),
        None => get_new_password(
            &format!("Enter export key for {}: ", &username),
            "Reenter export key: "
            ),
    };

    let passphrase = match matches.value_of("passphrase") {
        Some(p) => p.to_owned(),
        None => get_password( "Passphrase with which to decrypt keyfile: "),
    };

    let input: ExportedKey = match matches.value_of("file") {
        Some(f) => {
            let mut file = fs::File::open(f).expect("Unable to open the file");
            let mut buffer = String::new();
            file.read_to_string(&mut buffer).expect("Could not read file.");
            serde_json::from_str(&buffer).expect("Could not parse json.")
        },
        None => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer).expect("Could not read stdin.");
            serde_json::from_str(&buffer).expect("could not parse json.")
        },
    };

    let mut user = User::new_from_export_key (
        &username, 
        &password, 
        &export_key, 
        &input, 
        &passphrase)
        .expect("Could not create user");

    let connection = establish_connection().unwrap();

    match user.save(&connection) {
        Ok(_) => println!("User \"{}\" created successfully.", username),
        Err(e) => eprintln!("Could not save new user. Error \"{}\"", e),
    }
}

