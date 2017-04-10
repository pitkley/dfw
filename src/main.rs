// Increase the compiler's recursion limit for the `error_chain` crate.
#![recursion_limit = "1024"]

extern crate boondock;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;
extern crate toml;

use std::fs::File;
use std::io::prelude::*;

use boondock::{ContainerListOptions, Docker};

mod errors {
    error_chain! { }
}

use errors::*;

#[derive(Deserialize)]
struct Config {
    ip: String,
    port: Option<u16>,
    keys: Keys,
}

#[derive(Deserialize)]
struct Keys {
    github: String,
    travis: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DFW {
    external_network_interface: Option<String>,
    initialization: Option<DFWInit>,
    container_to_container: Option<CTC>,
}

#[derive(Deserialize, Debug)]
struct DFWInit {
    filter: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct CTC {
    default_policy: String,
    rules: Option<Vec<Rule>>,
}

#[derive(Deserialize, Debug)]
struct Rule {
    network: String,
    external_network_interface: Vec<String>,
    action: String,
}

fn load() -> Result<DFW> {
    let mut file = File::open("conf.toml").chain_err(|| "unable to read file conf.toml")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).chain_err(|| "unable to read file contents")?;

    toml::from_str::<DFW>(&contents).chain_err(|| "unable to load TOML")
}

fn run() -> Result<()> {
    let config: Config = toml::from_str(r#"
        ip = "127.0.0.1"

        [keys]
        github = 'xxxx'
        travis = 'yyyy'
    "#).unwrap();

    assert_eq!(config.ip, "127.0.0.1");
    assert_eq!(config.port, None);
    assert_eq!(config.keys.github, "xxxx");
    assert_eq!(config.keys.travis.as_ref().unwrap(), "yyyy");

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

    println!("-- single network");
    let network = d.network("paperless_default").unwrap().unwrap();
    println!("{}: {}", network.Id, network.Name);
    println!("{:#?}", network.Containers);
    println!();

    println!("--- TOML ---");
    let toml = load()?;
    println!("{:#?}", toml);

    Ok(())
}

quick_main!(run);

