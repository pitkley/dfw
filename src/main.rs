// Increase the compiler's recursion limit for the `error_chain` crate.
#![recursion_limit = "1024"]

// Import external libraries
extern crate boondock;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate toml;

// declare modules
mod errors;
mod types;

use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;

use boondock::{ContainerListOptions, Docker};

use errors::*;
use types::*;

fn load() -> Result<DFW> {
    let mut file = BufReader::new(File::open("conf.toml")?);
    let mut contents = String::new();
    file.read_to_string(&mut contents)?; //.chain_err(|| "unable to read file contents")?;

    Ok(toml::from_str::<DFW>(&contents)?) //.chain_err(|| "unable to load TOML")
}

fn run() -> Result<()> {
    println!("--- CONTAINERS ---");
    let d = Docker::connect_with_defaults().unwrap();
    if let Ok(containers) = d.containers(ContainerListOptions::default().all()) {
        for container in &containers {
            println!("{}: {:?}", container.Id, container.Names);
        }
    }
    println!("\n");

    println!("--- NETWORKS ---");
    for network in &(d.networks().unwrap()) {
        println!("{}: {}", network.Id, network.Name);
        println!();
    }

    println!("--- TOML ---");
    let toml = load()?;
    println!("{:#?}", toml);
    println!("{}", toml.container_to_container.map_or("no ctc policy".to_string(), |e| e.default_policy));

    Ok(())
}

quick_main!(run);

