#![feature(proc_macro_hygiene, decl_macro)]

extern crate chrono;
extern crate clap;
#[macro_use] extern crate rocket;
extern crate serde;
extern crate serde_json;
#[macro_use] extern crate rocket_contrib;
#[macro_use] extern crate diesel;
#[macro_use] extern crate serde_derive;

extern crate base64;
extern crate clear_on_drop;

mod database;
mod encryption;
mod cli;
mod model;
//mod web;
mod error;

use clap::{App, SubCommand};

fn main() {
    let app = App::new("Identity Vault")
        .version("0.0.1")
        .author("Daniel W. <daniel@stonecottageweb.com>")
        .about("Stores keys and authenticates messages on behalf of the user.")
        .subcommand(cli::account::init())
        .subcommand(cli::application::init())
        //.subcommand(cli::client::init())
        //.subcommand(cli::export::init())
        //.subcommand(cli::import::init())
        .subcommand(cli::init::init())
        //.subcommand(cli::scope::init())
        //.subcommand(cli::sign::init())
        //.subcommand(SubCommand::with_name("run").about("Runs the identity server."))
        ;

    let matches = app.get_matches();

    if matches.is_present("init") {
        cli::init::run();
    }

    /*
    if matches.is_present("run") {
        web::run();
    }
    */

    /*
    if let Some(matches) = matches.subcommand_matches("export") {
        cli::export::run(matches);
    }
    */

    /*
    if let Some(matches) = matches.subcommand_matches("import") {
        cli::import::run(matches);
    }
    */


    if let Some(matches) = matches.subcommand_matches("account") {
        cli::account::run(matches);
    }

    if let Some(matches) = matches.subcommand_matches("application") {
        cli::application::run(matches);
    }

    /*
    if let Some(matches) = matches.subcommand_matches("client") {
        cli::client::run(matches);
    }
    */


    /*
    if let Some(matches) = matches.subcommand_matches("scope") {
        cli::scope::run(matches);
    }
    */


    /*
    if let Some(matches) = matches.subcommand_matches("sign") {
        cli::sign::run(matches);
    }
    */

}

