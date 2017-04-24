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

use chan::{Receiver, Sender};
use chan_signal::Signal;
use clap::{App, Arg, ArgGroup, ArgMatches};
use glob::glob;
use serde::Deserialize;
use shiplift::Docker;
use shiplift::builder::{EventFilter, EventFilterType, EventsOptions};

use dfwrs::ProcessDFW;
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

fn spawn_burst_monitor(burst_timeout: u64, s_trigger: Sender<()>, r_event: Receiver<()>) {
    enum Trigger {
        Event,
        After,
        None,
    }
    ::std::thread::spawn(move || {
        let dummy: Receiver<()> = {
            let (s_dummy, r_dummy) = chan::sync(0);
            // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
            ::std::mem::forget(s_dummy);
            r_dummy
        };
        let mut after: Receiver<()> = dummy.clone();

        loop {
            // The `unused_assignments` warning for the following variable is wrong, since
            // `trigger` is read at the match-statement.
            // Maybe related to:
            //   https://github.com/rust-lang/rfcs/issues/1710
            #[allow(unused_assignments)]
            let mut trigger: Trigger = Trigger::None;

            chan_select! {
                r_event.recv() => {
                    trigger = Trigger::Event;
                },
                after.recv() => {
                    trigger = Trigger::After;
                    s_trigger.send(());
                }
            }

            match trigger {
                Trigger::Event => after = chan::after(Duration::from_millis(burst_timeout)),
                Trigger::After => after = dummy.clone(),
                Trigger::None => {}
            }
        }
    });
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
        .arg(Arg::with_name("burst-timeout")
                 .takes_value(true)
                 .default_value("500")
                 .long("burst-timeout")
                 .value_name("TIMEOUT")
                 .help("Time to wait after a event was received before processing the rules, in \
                        milliseconds"))
        .arg(Arg::with_name("disable-event-monitoring")
                 .takes_value(false)
                 .long("--disable-event-monitoring")
                 .help("Disable Docker event monitoring"))
        .arg(Arg::with_name("run-once")
                 .takes_value(false)
                 .long("run-once")
                 .help("Process rules once, then exit."))
        .get_matches();
    println!("{:#?}", matches);

    let docker = match matches.value_of("docker-url") {
        Some(docker_url) => Docker::host(docker_url.parse()?),
        None => Docker::new(),
    };
    // Check if the docker instance is reachable
    docker.ping()?;

    // Create a dummy channel
    let load_interval = value_t!(matches.value_of("load-interval"), u64)?;
    let load_interval_chan = {
        let load_interval = value_t!(matches.value_of("load-interval"), u64)?;

        if load_interval > 0 {
            // If the load interval is greater than zero, we use a tick-channel
            chan::tick(Duration::from_secs(load_interval))
        } else {
            // Otherwise we use the dummy channel, which will never send and thus never receive any
            // messages to circumvent having multiple `chan_select!`s below.
            let (s_dummy, r_dummy) = chan::sync(0);
            // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
            ::std::mem::forget(s_dummy);

            r_dummy
        }
    };
    let monitor_events = !matches.is_present("disable-event-monitoring");
    let run_once = matches.is_present("run-once");

    let toml = load_config(&matches)?;
    let process: Box<Fn() -> Result<()>> = match value_t!(matches.value_of("load-mode"),
                                                          LoadMode)? {
        LoadMode::Once => Box::new(|| ProcessDFW::new(&docker, &toml)?.process()),
        LoadMode::Always => {
            Box::new(|| {
                         let toml = load_config(&matches)?;
                         ProcessDFW::new(&docker, &toml)?.process()
                     })
        }
    };

    // Initial processing
    process()?;

    if run_once || (!monitor_events && load_interval <= 0) {
        // Either run-once is specified or both events are not monitored and rules aren't processed
        // regularly -- process once, then exit.
        ::std::process::exit(0);
    }

    let event_trigger = if monitor_events {
        // Setup event monitoring
        let (s_trigger, r_trigger) = chan::sync(0);
        let (s_event, r_event) = chan::sync(0);
        let docker_url = matches.value_of("docker-url").map(|s| s.to_owned());
        let burst_timeout = value_t!(matches.value_of("burst-timeout"), u64)?;
        spawn_burst_monitor(burst_timeout, s_trigger, r_event);
        spawn_event_monitor(docker_url, s_event);

        r_trigger
    } else {
        let (s_dummy, r_dummy) = chan::sync(0);
        // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
        ::std::mem::forget(s_dummy);
        r_dummy
    };

    loop {
        chan_select! {
            load_interval_chan.recv() => {
                println!("load interval");
                process()?;
            },
            event_trigger.recv() => {
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
