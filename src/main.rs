// Increase the compiler's recursion limit for the `error_chain` crate.
#![recursion_limit = "1024"]

// Import external libraries
#[macro_use]
extern crate chan;
extern crate chan_signal;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate error_chain;
extern crate glob;
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

use std::ascii::AsciiExt;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::time::Duration;

use chan::Sender;
use chan_signal::Signal;
use clap::{App, Arg, ArgGroup, ArgMatches};
use glob::glob;
use serde::Deserialize;
use shiplift::Docker;
use shiplift::builder::{EventFilter, EventFilterType, EventsOptions};

use errors::*;
use types::*;

arg_enum! {
    #[derive(Debug)]
    pub enum LoadMode {
        Once,
        Always
    }
}

fn load_file<T>(file: &str) -> Result<T>
    where T: Deserialize
{
    let mut file = BufReader::new(File::open(file)?);
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    Ok(toml::from_str(&contents)?)
}

fn load_path<T>(path: &str) -> Result<T>
    where T: Deserialize
{
    let mut contents = String::new();
    for entry in glob(&format!("{}/*.toml", path)).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                let mut file = BufReader::new(File::open(path)?);
                file.read_to_string(&mut contents)?;
            }
            Err(e) => println!("{:?}", e),
        }
    }

    Ok(toml::from_str(&contents)?)
}

fn load_config(matches: &ArgMatches) -> Result<DFW> {
    let toml: DFW = if matches.is_present("config-file") {
        load_file(matches.value_of("config-file").unwrap())?
    } else if matches.is_present("config-path") {
        load_path(matches.value_of("config-path").unwrap())?
    } else {
        // This statement should be unreachable, since clap verifies that either config-file or
        // config-path is populated.
        // If we reach this anyway, bail.
        bail!("neither config-file nor config-path specified");
    };

    Ok(toml)
}

fn spawn_event_monitor(docker_url: Option<String>, s_event: Sender<()>) {
    ::std::thread::spawn(move || {
        let docker = match docker_url {
            Some(docker_url) => Docker::host(docker_url.parse().unwrap()),
            None => Docker::new(),
        };
        loop {
            println!("waiting for events");
            for event in
                docker
                    .events(&EventsOptions::builder()
                                 .filter(vec![EventFilter::Type(EventFilterType::Container)])
                                 .build())
                    .unwrap() {
                println!("got event: '{:?}'", event);
                match event.status {
                    Some(status) => {
                        match &*status {
                            "create" | "destroy" | "start" | "restart" | "die" | "stop" => {
                                s_event.send(());
                                break;
                            }
                            _ => continue,
                        }
                    }
                    None => continue,
                }
            }
        }
    });
}

fn run() -> Result<()> {
    // Signals should be set up as early as possible, to set proper signal masks to all threads
    let signal = chan_signal::notify(&[Signal::INT, Signal::TERM, Signal::HUP]);

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
        .arg(Arg::with_name("config-path")
                 .takes_value(true)
                 .long("config-path")
                 .value_name("PATH")
                 .help("Set a path with multiple TOML configuration files"))
        .group(ArgGroup::with_name("config")
                   .args(&["config-file", "config-path"])
                   .multiple(false)
                   .required(true))
        .arg(Arg::with_name("docker-url")
                 .takes_value(true)
                 .short("d")
                 .long("docker-url")
                 .value_name("URL")
                 .help("Set the url to the Docker instance (e.g. unix:///tmp/docker.sock)"))
        .arg(Arg::with_name("load-interval")
                 .takes_value(true)
                 .default_value("15")
                 .short("i")
                 .long("load-interval")
                 .value_name("INTERVAL")
                 .help("Interval between rule processing runs, in seconds (0 = disabled)"))
        .arg(Arg::with_name("load-mode")
                 .takes_value(true)
                 .short("m")
                 .long("load-mode")
                 .possible_values(LoadMode::variants()
                                      .iter()
                                      .map(|s| s.to_ascii_lowercase())
                                      .collect::<Vec<_>>()
                                      .iter()
                                      .map(|s| &**s)
                                      .collect::<Vec<_>>()
                                      .as_slice())
                 .default_value("once"))
        .get_matches();
    println!("{:#?}", matches);

    let docker = match matches.value_of("docker-url") {
        Some(docker_url) => Docker::host(docker_url.parse()?),
        None => Docker::new(),
    };
    // Check if the docker instance is reachable
    docker.ping()?;

    let ipt4 = iptables::new(false)?;
    let ipt6 = iptables::new(true)?;

    // Create a dummy channel
    let (_s_dummy, r_dummy) = chan::sync(0);
    let load_interval = {
        let load_interval = value_t!(matches.value_of("load-interval"), u64)?;

        if load_interval > 0 {
            // If the load interval is greater than zero, we use a tick-channel
            chan::tick(Duration::from_secs(load_interval))
        } else {
            // Otherwise we use the dummy channel, which will never send and thus never receive any
            // messages to circumvent having multiple `chan_select!`s below.
            r_dummy
        }
    };

    let toml = load_config(&matches)?;
    let process: Box<Fn() -> Result<()>> = match value_t!(matches.value_of("load-mode"),
                                                          LoadMode)? {
        LoadMode::Once => Box::new(|| dfwrs::process(&docker, &toml, &ipt4, &ipt6)),
        LoadMode::Always => {
            Box::new(|| {
                         let toml = load_config(&matches)?;
                         dfwrs::process(&docker, &toml, &ipt4, &ipt6)
                     })
        }
    };

    // Initial processing
    process()?;

    // Setup event monitor
    let (s_event, r_event) = chan::sync(0);
    let docker_url = matches.value_of("docker-url").map(|s| s.to_owned());
    spawn_event_monitor(docker_url, s_event);

    loop {
        chan_select! {
            load_interval.recv() => {
                println!("load interval");
                process()?;
            },
            r_event.recv() => {
                println!("received event trigger");
                process()?;
            },
            signal.recv() -> signal => {
                match signal {
                    Some(Signal::INT) | Some(Signal::TERM) => {
                        break;
                    }
                    Some(Signal::HUP) => {
                        process()?;
                    }
                    Some(_) => { bail!("got unexpected signal '{:?}'", signal); }
                    None => { bail!("signal was empty"); }
                }
            }
        }
    }

    Ok(())
}

quick_main!(run);
