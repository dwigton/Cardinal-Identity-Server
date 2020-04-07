use base64::{encode};
use database::establish_connection;
use clap::{App, Arg, ArgMatches, SubCommand};
use cli::{get_input, get_password};
use model::client::ClientApp;
use io::signature_request::SignatureRequest;
use std::io::prelude::*;
use std::fs::File;
use std::fs;
//use serde_json::Result;

pub fn init() -> App<'static, 'static> {
    SubCommand::with_name("sign")
        .about("Sign an arbitrary piece of data.")
        .arg(Arg::with_name("outputfile")
             .short("o")
             .long("outputfile")
             .help("Write signature to file.")
             .value_name("OUTPUT")
             .takes_value(true)
            )
        .arg(Arg::with_name("file")
             .short("f")
             .long("file")
             .help("Input data file")
             .value_name("INPUT")
             .takes_value(true)
            )
        .arg(Arg::with_name("input_example")
             .short("i")
             .long("input_example")
             .help("Write an example input file to the output file.")
             .takes_value(false)
            )
}

pub fn run(matches: &ArgMatches) {

    let connection = establish_connection().unwrap();

    if matches.is_present("input_example") {

        let example_request = SignatureRequest::random();

        match matches.value_of("output") {
            Some(f) => {
                let output_stream = File::create(&f).unwrap();
                serde_cbor::to_writer(output_stream, &example_request).expect("Could not write data to file.");
            },
            None => {
                let output_stream = std::io::stdout();
                serde_cbor::to_writer(output_stream, &example_request).expect("Could not write data to file.");
            },
        };

        return ();
    }

    let file = match matches.value_of("file") {
        Some(p) => p.to_owned(),
        None => get_input("Input File: "),
    };

    let f = File::open(file).expect("Could not open file for reading.");

    let input: SignatureRequest = serde_json::from_reader(f).expect("File format not recognized.");

    println!("{}", encode(&input.client_id));
}

