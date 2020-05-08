use std::fs::OpenOptions;
use std::io::{Write, BufReader, BufRead};
use clap::{App, SubCommand};
use database;
use cli::{get_input, get_new_password};
use model::account::{Account};
use encryption::random_int_256;
use database::establish_connection;
use base64::encode;

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("init").about("Initializes application before use.")
}

pub fn run() {
    println!("Enter the postgres database url. The format should be \"postgres://<username>:<password>@<host>/<database>\"");
    let mut database_url: String;

    loop {
        database_url = get_input("DATABASE_URL: ");
        if database::can_connect_to_url(&database_url) {
            break;
        }

        println!("Cannot connection with url {}.", database_url);
    }

    set_env_variable("DATABASE_URL", database_url.as_str());

    let admin_user_name = get_input("Administrator User Name: ");
    let password = get_new_password("Administrator User Password: ", "Reenter Admin User Password: ");
    let export_key = encode(&random_int_256());

    let mut account = Account::new(&admin_user_name, &password, &export_key, true);

    let connection = establish_connection().unwrap();

    match account.save(&connection) {
        Ok(_) => (),
        Err(e) => println!("Could not save new account. Error \"{}\"", e),
    }
}

fn set_env_variable(variable: &str, value: &str) {
    let result: String;

    {
        let f = OpenOptions::new().read(true).open(".env");

        result = match f {
            Ok(f) => {
                let file = BufReader::new(&f);
                let mut rewrite = String::new();

                for l in file.lines() {
                    let line = l.unwrap();
                    if line.starts_with(variable) {
                        rewrite.push_str(&format!("{}={}\n", variable, value));
                    } else {
                        rewrite.push_str(&format!("{}\n", line));
                    }
                }

                rewrite
            }
            _ => {
                format!("{}={}\n", variable, value)
            }
        }
    }

    let mut f = OpenOptions::new()
        .write(true)
        .append(false)
        .create(true)
        .truncate(true)
        .open(".env")
        .expect("could not open or create .env");
    
    f.write_all(result.as_bytes()).expect("Could not write to .env");
}
