use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password};
use model::user::User;
use model::scope::Scope;

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("scope")
     .about("scope administration commands.")
     .subcommand(SubCommand::with_name("add")
          .about("Add a new grant scope.")
          .arg(Arg::with_name("write")
               .short("w")
               .long("write")
               .help("makes the scope writeable")
               .value_name("WRITE")
          )
          .arg(Arg::with_name("username")
               .short("u")
               .long("username")
               .help("The user name for the account to which to add the grant scope")
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
          .arg(Arg::with_name("code")
               .short("c")
               .long("code")
               .help("A specific identifier for the grant on a particular application. e.g. std::social::write")
               .value_name("CODE")
               .takes_value(true)
          )
          .arg(Arg::with_name("display_name")
               .short("d")
               .long("display")
               .help("Human readable version of the scope.")
               .value_name("DISPLAY_KEY")
               .takes_value(true)
          )
          .arg(Arg::with_name("description")
               .short("D")
               .long("description")
               .help("An explination of what this scope enables.")
               .value_name("EXPORT_KEY")
               .takes_value(true)
          )
     )
     .subcommand(SubCommand::with_name("list")
          .about("List user scopes.")
          .arg(Arg::with_name("username")
               .short("u")
               .long("username")
               .help("Show scopes for one user.")
               .value_name("USERNAME")
               .takes_value(true)
          )
      )
}

pub fn run(matches: &ArgMatches) {

    let connection = establish_connection().unwrap();

    // Create new scope.
    if let Some(matches) = matches.subcommand_matches("add") {

        let username = match matches.value_of("username") {
            Some(u) => u.to_owned(),
            None => get_input("Username: "),
        };

        let password = match matches.value_of("password") {
            Some(p) => p.to_owned(),
            None => get_password("User password: "),
        };

        let code = match matches.value_of("code") {
            Some(p) => p.to_owned(),
            None => get_input("Scope code: "),
        };

        let is_write = matches.is_present("write");

        let user = User::load(&username, &password, &connection).expect("Username and password not recognized.");

        let mut scope = Scope::new(&code, is_write, &user).expect("Invalid user");

        match scope.save(&connection) {
            Ok(_) => println!("Scope \"{}\" created successfully.", code),
            Err(e) => eprintln!("Could not save new scope. Error \"{}\"", e),
        }

    }

    // List scopes.
    if let Some(matches) = matches.subcommand_matches("list") {

        let records = match matches.subcommand_matches("username") {
            Some(username) => {

                let name = match username.value_of("username") {
                    Some(u) => u.to_owned(),
                    None => get_input("Username: "),
                };

                let user_id = User::id_from_username(&name, &connection).expect("Could not find user");
                let mut write_scopes = Scope::load_all_for_user(user_id, true, &connection).expect("Error loading scopes for user");
                let mut read_scopes = Scope::load_all_for_user(user_id, false, &connection).expect("Error loading scopes for user");
                write_scopes.append(&mut read_scopes);
                
                write_scopes
            }
            None => {
                Scope::load_all(&connection).expect("Error loading scopes.")
            }
        };

        for i in 0..records.len() {
            println!("{}", records[i].code);
        }
    }
}

