#[macro_use] extern crate rocket;
#[macro_use] extern crate diesel;
#[macro_use] extern crate serde_derive;

mod cli;
mod database;
mod encryption;
mod model;
mod web;
mod error;

use clap::App;
use clap::ArgMatches;
use clap::SubCommand;
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
        .subcommand(SubCommand::with_name("run").about("Runs the identity server."))
        ;

    let matches: ArgMatches = app.get_matches();

    let status: Result<()> = match matches.subcommand() {
        ("init", _)              => cli::init::run(),
        ("account", Some(m))     => cli::account::run(m),
        ("application", Some(m)) => cli::application::run(m),
        ("client", Some(m))      => cli::client::run(m),
        ("run", _)               => web::run(),
        (c, _)                   => bail!("Subcommand {} not recognized.", c),
    };

    status
}
