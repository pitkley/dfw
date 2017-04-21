// Increase the compiler's recursion limit for the `error_chain` crate.
#![recursion_limit = "1024"]

// Import external libraries
#[macro_use]
extern crate clap;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate error_chain;
extern crate iptables;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate shiplift;
extern crate toml;
extern crate url;

// declare modules
mod dfwrs;
mod errors;
mod types;

use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;

use clap::{App, Arg};
use serde::Deserialize;
use shiplift::Docker;

use errors::*;
use types::*;

fn load<T>(filepath: &str) -> Result<T>
    where T: Deserialize
{
    let mut file = BufReader::new(File::open(filepath)?);
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    Ok(toml::from_str::<T>(&contents)?)
}

fn run() -> Result<()> {
    let matches = App::new("dfwrs")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Docker Firewall Framework, in Rust")
        .arg(Arg::with_name("config-file")
                 .takes_value(true)
                 .short("c")
                 .long("config-file")
                 .value_name("FILE")
                 .help("Set the configuration file"))
        //.arg(Arg::with_name("config-path")
        //         .takes_value(true)
        //         .long("config-path")
        //         .value_name("PATH")
        //         .help("Set a path with multiple TOML configuration files"))
        //.group(ArgGroup::with_name("config")
        //           .args(&["config-file", "config-path"])
        //           .multiple(false)
        //           .required(true))
        .arg(Arg::with_name("docker-url")
                 .takes_value(true)
                 .short("d")
                 .long("docker-url")
                 .value_name("URL")
                 .help("Set the url to the Docker instance (e.g. unix:///tmp/docker.sock)"))
        .get_matches();
    println!("{:#?}", matches);

    let docker = match matches.value_of("docker-url") {
        Some(docker_url) => Docker::host(docker_url.parse()?),
        None => Docker::new(),
    };

    let config_file = matches.value_of("config-file").unwrap();
    let toml: DFW = load(config_file)?;
    let ipt4 = iptables::new(false).unwrap();
    let ipt6 = iptables::new(true).unwrap();

    dfwrs::process(&docker, &toml, &ipt4, &ipt6)?;

    Ok(())
}

quick_main!(run);
