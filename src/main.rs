#![feature(proc_macro_hygiene, decl_macro)]

extern crate chrono;
extern crate clap;
//#[macro_use] extern crate rocket;
extern crate serde;
extern crate serde_json;
//#[macro_use] extern crate rocket_contrib;
#[macro_use]
extern crate diesel;
//#[macro_use] extern crate serde_derive;

extern crate base64;
extern crate clear_on_drop;
extern crate anyhow;

mod cli;
mod database;
mod encryption;
mod model;
//mod web;
mod error;

use clap::App;
use clap::ArgMatches;
use anyhow::{bail, Result};

fn main() -> Result<()> {
    let app = App::new("Identity Vault")
        .version("0.0.1")
        .author("Daniel W. <daniel@stonecottageweb.com>")
        .about("Stores keys and authenticates messages on behalf of the user.")
        .subcommand(cli::account::init())
        .subcommand(cli::application::init())
        .subcommand(cli::client::init())
        //.subcommand(cli::export::init())
        //.subcommand(cli::import::init())
        .subcommand(cli::init::init())
        //.subcommand(cli::scope::init())
        //.subcommand(cli::sign::init())
        //.subcommand(SubCommand::with_name("run").about("Runs the identity server."))
        ;

    let matches: ArgMatches = app.get_matches();

    let status: Result<()> = match matches.subcommand() {
        ("init", _)              => cli::init::run(),
        ("account", Some(m))     => cli::account::run(m),
        ("application", Some(m)) => cli::application::run(m),
        ("client", Some(m))      => cli::client::run(m),
        (c, _)                   => bail!("Subcommand {} not recognized.", c),
    };

    /*
    if matches.is_present("run") {
        web::run();
    }
    */

    status
}
