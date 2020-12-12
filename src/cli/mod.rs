pub mod account;
pub mod application;
pub mod client;
pub mod init;
//pub mod export;
//pub mod import;
//pub mod scope;
//pub mod sign;

use std::io::{stdin, stdout, Write};

pub fn get_input(message: &str) -> String {
    let mut input_string = String::new();

    print!("{}", message);
    stdout().flush().expect("Could not flush output buffer.");

    stdin()
        .read_line(&mut input_string)
        .expect("Entered string not valid.");

    if let Some('\n') = input_string.chars().next_back() {
        input_string.pop();
    }

    if let Some('\r') = input_string.chars().next_back() {
        input_string.pop();
    }

    input_string
}

pub fn get_new_password(message: &str, reenter_message: &str) -> String {
    let mut pass: String;
    let mut pass2: String;

    loop {
        pass = rpassword::prompt_password_stdout(message).unwrap();
        pass2 = rpassword::prompt_password_stdout(reenter_message).unwrap();

        if pass == pass2 {
            break;
        }

        println!("Passwords do not match!");
    }

    pass
}

pub fn get_password(message: &str) -> String {
    rpassword::prompt_password_stdout(message).unwrap()
}
