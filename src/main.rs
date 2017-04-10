extern crate boondock;
#[macro_use]
extern crate serde_derive;
extern crate toml;

use std::fs::File;
use std::io::prelude::*;

//use boondock::{ContainerListOptions, Docker};

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

fn load() -> Result<DFW, String> {
    let mut file: File = match File::open("conf.toml") {
        Ok(file) => file,
        Err(err) => return Err(format!("f: {}", err.to_string())),
    };
    let mut contents = String::new();
    if let Err(err) = file.read_to_string(&mut contents) {
        return Err(format!("c: {}", err.to_string()));
    }

    match toml::from_str::<DFW>(&contents) {
        Ok(toml) => Ok(toml),
        Err(err) => return Err(format!("f: {}", err.to_string())),
    }
}

#[allow(dead_code)]
fn load2() -> DFW {
    let mut file = File::open("conf.toml").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents);
    toml::from_str(&contents).unwrap()
}

fn main() {
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

    /*let d = Docker::connect_with_defaults().unwrap();
    if let Ok(containers) = d.containers(ContainerListOptions::default().all()) {
        for container in &containers {
            println!("{}: {:?}", container.Id, container.Names);
        }
    }*/

    match load() {
        Ok(r) => println!("r: {:?}", r),
        Err(s) => println!("err: {}", s),
    }
}

