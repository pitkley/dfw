// Increase the compiler's recursion limit for the `error_chain` crate.
#![recursion_limit = "1024"]

// Import external libraries
extern crate boondock;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate error_chain;
extern crate iptables;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate toml;

// declare modules
mod dfwrs;
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
    file.read_to_string(&mut contents)?;

    Ok(toml::from_str::<DFW>(&contents)?)
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
    let toml: DFW = load()?;
    println!("{:#?}", toml);

    let res: () = dfwrs::process(toml)?;
    println!("{:?}", res);

    println!();

    println!("--- IPTABLES ---");
    let ipt4 = iptables::new(false).unwrap();
    let ipt6 = iptables::new(true).unwrap();
    println!("4: {}, 6: {}", ipt4.cmd, ipt6.cmd);

    let chains: Vec<String> = ipt4.list_chains("filter")?;
    for chain in &chains {
        println!("chain: {}", chain);
    }

    Ok(())
}

quick_main!(run);
