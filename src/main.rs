// Copyright 2017 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! # DFWRS - Docker Firewall Framework in Rust
//!
//! `dfwrs` is conceptually based on the [Docker Firewall Framework, `dfwfw`][dfwfw-github]. Its
//! goal is to make firewall administration with Docker simpler, but also more extensive by trying
//! to replace the Docker built-in firewall handling by direct interaction with iptables.
//!
//! This is accomplished by a flexible configuration which defines how the firewall should be built
//! up. While DFWRS is running, Docker container events will be monitored and the rules rebuilt
//! when necessary.
//!
//! See [DFWFW's README][dfwfw-readme] for more insight. Most of what you will read there will be
//! applicable to DFWRS.
//!
//! ## Configuration
//!
//! The general configuration happens across six categories:
//!
//! * `defaults`
//!
//!     This category defines global, default values to be used by DFWRS and the other categories.
//!
//! * `container_to_container`
//!
//!     This controls the communication between containers and across [Docker
//!     networks][docker-networks].
//!
//! * `container_to_wider_world`
//!
//!     This controls if and how containers may access the wider world, i.e. what they can
//!     communicate across the `OUTPUT` chain on the host.
//!
//! * `container_to_host`
//!
//!     To restrict or allow access to the host, this section is used.
//!
//! * `wider_world_to_container`
//!
//!     This controls how the wider world, i.e. whatever comes in through the `INPUT` chain on the
//!     host, can communicate with a container or a Docker network.
//!
//! * `container_dnat`
//!
//!     This category allows you to define specific rules for destination network address
//!     translation, even or especially across Docker networks.
//!
//! One category which DFWFW covers that is not (yet) implemented in DFWRS is
//! `container_internals`, that is configuring iptables rules within containers.
//!
//! See the [examples][examples] *(TODO)*, and the [configuration types][types.rs] for a detailed
//! description of every configuration section.
//!
//! ## Supported Docker versions
//!
//! At least Docker 1.9.0 is required, since we heavily rely on the Docker [networking
//! feature][docker-networks] which was introduced in 1.9.0.
//!
//! DFWRS has been successfully tested under the following Docker versions:
//!
//! * `17.03.1-ce`
//!
//! * `17.04.0-ce`
//!
//! It is planned to introduce some form of automated testing to cover as many Docker versions as
//! possible.
//!
//! ## Installation
//!
//! While you can use Cargo to install `dfwrs` as a binary, using the Docker image is the preferred
//! way to go, especially if you don't want to install Rust and Cargo on your host:
//!
//! ```console
//! $ docker pull pitkley/dfwrs:0.2
//! $ docker run -d \
//!       --name=dfwrs \
//!       -v /var/run/docker.sock:/var/run/docker.sock:ro \
//!       -v /path/to/your/config:/config \
//!       --net host --cap-add=NET_ADMIN \
//!       pitkley/dfwrs --config-path /config
//! ```
//!
//! This will download a lightweight image, coming in at under 6 MB, and subsequently run it using
//! your configuration.
//!
//! ## Motivation for this reimplementation
//!
//! I have reimplemented DFWFW in Rust for two reasons:
//!
//! 1. DFWFW has lost compatibility with the Docker API starting with release 17.04.0-ce.
//!
//!     This is very likely due to a change in Dockers web API regarding getting networks and their
//!     containers, see [this relevant issue][moby-issue-32686]. Now, it would almost certainly have
//!     been easier to fix this issue in DFWFW -- if not for me, maybe for the maintainer. I have
//!     [created an issue][dfwfw-issue-13] to give the DFWFW maintainer a heads-up.
//!
//! 2. But the main reason for this reimplementation was that I found a real-life project to tackle
//!    with Rust. This project allowed me to delve into quite a few different aspects and facets of
//!    Rust and especially its eco-system, amongst others:
//!
//!   * [`clap`][crates-clap], for parsing of command line arguments
//!   * [`chan`][crates-chan], for easy messaging and coordination between threads
//!   * [`error_chain`][crates-error_chain], for simplified application wide error handling
//!   * [Serde][crates-serde], for deserialization of the TOML configuration
//!   * [`slog`][crates-slog], for structured logging
//!
//!     Disregarding the obvious hair-pulling moments regarding ownership, borrowing and lifetimes,
//!     my experience with Rust, and its brillant eco-system has been an absolute pleasure.
//!
//! ## License
//!
//! DFWRS is licensed under either of
//!
//! * Apache License, Version 2.o, ([LICENSE-APACHE](LICENSE-APACHE) or
//!   http://www.apache.org/licenses/LICENSE-2.0)
//! * MIT license ([LICENSE-MIT](LICENSE-MIT) or
//!   http://opensource.org/licenses/MIT)
//!
//! at your option.
//!
//! ### Contribution
//!
//! Unless you explicitly state otherwise, any contribution intentionally submitted
//! for inclusion in DFWRS by you, as defined in the Apache-2.0 license, shall be
//! dual licensed as above, without any additional terms or conditions.
//!
//!
//! [crates-clap]: https://crates.io/crates/clap
//! [crates-chan]: https://crates.io/crates/chan
//! [crates-error_chain]: https://crates.io/crates/error-chain
//! [crates-serde]: https://crates.io/crates/serde
//! [crates-slog]: https://crates.io/crates/slog
//!
//! [dfwfw-github]: https://github.com/irsl/dfwfw
//! [dfwfw-issue-13]: https://github.com/irsl/dfwfw/issues/13
//! [dfwfw-readme]: https://github.com/irsl/dfwfw/blob/master/README.md
//!
//! [docker-networks]: https://docs.docker.com/engine/userguide/networking/
//!
//! [moby-issue-32686]: https://github.com/moby/moby/issues/32686
//!
//! [types.rs]: types/index.html

// Increase the compiler's recursion limit for the `error_chain` crate.
#![recursion_limit = "1024"]
#![warn(missing_docs)]

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
extern crate iptables as ipt;
extern crate libc;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate shiplift;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;
extern crate time;
extern crate toml;
extern crate url;

// declare modules
mod dfwrs;
mod errors;
mod iptables;
pub mod types;

use std::ascii::AsciiExt;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::thread;
use std::time::Duration;

use std::os::unix::thread::JoinHandleExt;

use chan::{Receiver, Sender};
use chan_signal::Signal;
use clap::{App, Arg, ArgGroup, ArgMatches};
use glob::glob;
use serde::Deserialize;
use shiplift::Docker;
use shiplift::builder::{EventFilter, EventFilterType, EventsOptions};
use slog::{Logger, Drain};

use dfwrs::ProcessDFW;
use errors::*;
use iptables::IPTablesProxy;
use types::*;

arg_enum! {
    #[derive(Debug)]
    enum LoadMode {
        Once,
        Always
    }
}

fn load_file<'de, T>(file: &str, contents: &'de mut String) -> Result<T>
    where T: Deserialize<'de>
{
    let mut file = BufReader::new(File::open(file)?);
    file.read_to_string(contents)?;
    Ok(toml::from_str(contents)?)
}

fn load_path<'de, T>(path: &str, contents: &'de mut String) -> Result<T>
    where T: Deserialize<'de>
{
    for entry in glob(&format!("{}/*.toml", path)).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                let mut file = BufReader::new(File::open(path)?);
                file.read_to_string(contents)?;
            }
            Err(e) => println!("{:?}", e),
        }
    }

    Ok(toml::from_str(contents)?)
}

fn load_config(matches: &ArgMatches) -> Result<DFW> {
    // TODO somehow get rid of this lifetime-workaround
    let mut contents = String::new();
    let toml: DFW = if matches.is_present("config-file") {
        load_file(matches.value_of("config-file").unwrap(), &mut contents)?
    } else if matches.is_present("config-path") {
        load_path(matches.value_of("config-path").unwrap(), &mut contents)?
    } else {
        // This statement should be unreachable, since clap verifies that either config-file or
        // config-path is populated.
        // If we reach this anyway, bail.
        bail!("neither config-file nor config-path specified");
    };

    Ok(toml)
}

fn spawn_burst_monitor(burst_timeout: u64,
                       s_trigger: Sender<()>,
                       r_event: Receiver<()>,
                       r_exit: Receiver<()>,
                       logger: &Logger)
                       -> thread::JoinHandle<()> {
    let logger = logger.new(o!("thread" => "burst_monitor"));

    #[derive(Debug)]
    enum Trigger {
        Event,
        After,
        None,
    }
    thread::spawn(move || {
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
                    trace!(logger, "Received docker event");
                    trigger = Trigger::Event;
                },
                after.recv() => {
                    trace!(logger, "After timer ran out, sending trigger");
                    trigger = Trigger::After;
                    s_trigger.send(());
                },
                r_exit.recv() => {
                    trace!(logger, "Received exit event");
                    break;
                }
            }

            trace!(logger, "Resetting after channel";
                   o!("trigger" => format!("{:?}", trigger)));
            match trigger {
                Trigger::Event => after = chan::after(Duration::from_millis(burst_timeout)),
                Trigger::After => after = dummy.clone(),
                Trigger::None => {}
            }
        }
    })
}

fn spawn_event_monitor(docker_url: Option<String>,
                       s_event: Sender<()>,
                       logger: &Logger)
                       -> thread::JoinHandle<()> {
    let logger = logger.new(o!("thread" => "event_monitor"));

    thread::spawn(move || {
        let docker = match docker_url {
            Some(docker_url) => Docker::host(docker_url.parse().unwrap()),
            None => Docker::new(),
        };
        loop {
            trace!(logger, "Waiting for events");
            for event in
                docker
                    .events(&EventsOptions::builder()
                                 .filter(vec![EventFilter::Type(EventFilterType::Container)])
                                 .build())
                    .unwrap() {
                trace!(logger, "Received event";
                       o!("event" => format!("{:?}", &event)));
                match event.status {
                    Some(ref status) => {
                        match &**status {
                            "create" | "destroy" | "start" | "restart" | "die" | "stop" => {
                                trace!(logger, "Trigger channel about event";
                                       o!("event" => format!("{:?}", event)));
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
    })
}

#[cfg(unix)]
fn run(signal: Receiver<Signal>, root_logger: &Logger) -> Result<()> {
    info!(root_logger, "Application starting";
          o!("version" => crate_version!(),
             "started_at" => format!("{}", time::now().rfc3339())));

    trace!(root_logger, "Parsing command line arguments");
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
                 .default_value("0")
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
                 .default_value("once")
                 .help("Define if the config-files get loaded once, or before every run"))
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
    debug!(root_logger, "Parsed command line arguments: {:#?}", matches);

    let docker = match matches.value_of("docker-url") {
        Some(docker_url) => Docker::host(docker_url.parse()?),
        None => Docker::new(),
    };
    // Check if the docker instance is reachable
    trace!(root_logger, "Pinging docker");
    docker.ping()?;

    // Create a dummy channel
    let load_interval = value_t!(matches.value_of("load-interval"), u64)?;
    let load_interval_chan = {
        let load_interval = value_t!(matches.value_of("load-interval"), u64)?;

        if load_interval > 0 {
            // If the load interval is greater than zero, we use a tick-channel
            trace!(root_logger, "Creating tick channel";
                   o!("load_interval" => load_interval));
            chan::tick(Duration::from_secs(load_interval))
        } else {
            // Otherwise we use the dummy channel, which will never send and thus never receive any
            // messages to circumvent having multiple `chan_select!`s below.
            trace!(root_logger, "Creating dummy channel";
                   o!("load_interval" => load_interval));
            let (s_dummy, r_dummy) = chan::sync(0);
            // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
            ::std::mem::forget(s_dummy);

            r_dummy
        }
    };
    let monitor_events = !matches.is_present("disable-event-monitoring");
    trace!(root_logger, "Monitoring events: {}", monitor_events;
           o!("monitor_events" => monitor_events));

    let run_once = matches.is_present("run-once");
    trace!(root_logger, "Run once: {}", run_once;
           o!("run_once" => run_once));

    let toml = load_config(&matches)?;
    info!(root_logger, "Initial configuration loaded");
    debug!(root_logger, "Loaded config: {:#?}", toml);

    let ipt4 = IPTablesProxy(ipt::new(false)?);
    let ipt6 = IPTablesProxy(ipt::new(true)?);

    let process: Box<Fn() -> Result<()>> = match value_t!(matches.value_of("load-mode"),
                                                          LoadMode)? {
        LoadMode::Once => {
            trace!(root_logger, "Creating process closure according to load mode";
                   o!("load_mode" => "once"));
            Box::new(|| {
                         ProcessDFW::new(&docker, &toml, &ipt4, &ipt6, &root_logger)?
                             .process()
                     })
        }
        LoadMode::Always => {
            trace!(root_logger, "Creating process closure according to load mode";
                   o!("load_mode" => "always"));
            Box::new(|| {
                         let toml = load_config(&matches)?;
                         info!(root_logger, "Reloaded configuration before processing");
                         debug!(root_logger, "Reloaded config: {:#?}", toml);

                         ProcessDFW::new(&docker, &toml, &ipt4, &ipt6, &root_logger)?
                             .process()
                     })
        }
    };
    trace!(root_logger,
           "Load mode: {:?}",
           matches.value_of("load-mode"));

    info!(root_logger, "Application started";
          "version" => crate_version!(),
          "started_at" => format!("{}", time::now().rfc3339()));

    // Initial processing
    info!(root_logger, "Start first processing");
    process()?;

    if run_once || (!monitor_events && load_interval <= 0) {
        // Either run-once is specified or both events are not monitored and rules aren't processed
        // regularly -- process once, then exit.
        info!(root_logger,
              "Run once specified (or load-interval is zero and events aren't monitored), exiting";
              o!("version" => crate_version!(),
                 "exited_at" => format!("{}", time::now().rfc3339())));
        ::std::process::exit(0);
    }

    let (event_trigger, terminate_threads, thread_handles) = if monitor_events {
        // Setup event monitoring
        trace!(root_logger, "Setup event monitoring channel";
               o!("monitor_events" => monitor_events));

        let (s_burst_exit, r_burst_exit) = chan::sync(0);
        let (s_trigger, r_trigger) = chan::sync(0);
        let (s_event, r_event) = chan::sync(0);
        let docker_url = matches.value_of("docker-url").map(|s| s.to_owned());
        let burst_timeout = value_t!(matches.value_of("burst-timeout"), u64)?;

        trace!(root_logger, "Start burst monitoring thread";
               o!("burst_timeout" => burst_timeout));
        let burst_handle = spawn_burst_monitor(burst_timeout,
                                               s_trigger,
                                               r_event,
                                               r_burst_exit,
                                               &root_logger);

        trace!(root_logger, "Start event monitoring thread";
               o!("docker_url" => &docker_url));
        let event_handle = spawn_event_monitor(docker_url, s_event, &root_logger);
        let event_pthread_t = event_handle.as_pthread_t();

        let terminate_threads: Box<Fn() -> ()> = Box::new(move || {
            trace!(root_logger, "Triggering burst thread to exit");
            s_burst_exit.send(());
            unsafe {
                // The event-thread is stuck in a potentially indefinitely blocking for loop,
                // waiting for a Docker event to happen.
                //
                // I can think of two ways to exit it:
                //
                //   1. Artifically produce an event, which unblocks the loop and lets us check for
                //      an exit trigger
                //   2. Kill the thread
                //
                // While artifically producing an event sounds cleaner, it would require to
                // actually cause an event on the host we are running on, i.e. starting a
                // container, or maybe pulling a non-existant image.
                //
                // I don't necessarily want to interfere with the running host, although causing an
                // event for something that will be known to fail might be an option.
                //
                // The alternative, killing the thread, requires the unix-specific `JoinHandle`
                // extensions to get a (numeric) handle to the thread, which can then unsafely be
                // killed using `libc`.
                //
                // We have to send the "hardest" signal, SIGKILL, since both SIGINT and SIGTERM are
                // captured at the very start of the main thread, and this propagates to the child
                // thread.
                //
                // TODO: find a cleaner way!
                trace!(root_logger, "Sending SIGKILL to event thread";
                       o!("pthread_t" => event_pthread_t));
                libc::pthread_kill(event_pthread_t, libc::SIGKILL);
            }
        });

        (r_trigger, terminate_threads, vec![burst_handle, event_handle])
    } else {
        trace!(root_logger, "Creating dummy channel";
               o!("monitor_events" => monitor_events));
        let (s_dummy, r_dummy) = chan::sync(0);
        // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
        ::std::mem::forget(s_dummy);

        let terminate_threads: Box<Fn() -> ()> = Box::new(|| {});
        (r_dummy, terminate_threads, vec![])
    };

    loop {
        chan_select! {
            load_interval_chan.recv() => {
                info!(root_logger, "Load interval ticked, starting processing");
                process()?;
            },
            event_trigger.recv() => {
                info!(root_logger, "Received Docker events, starting processing");
                process()?;
            },
            signal.recv() -> signal => {
                match signal {
                    Some(Signal::INT) | Some(Signal::TERM) => {
                        info!(root_logger, "Received kill-signal, exiting";
                              o!("signal" => format!("{:?}", signal)));

                        trace!(root_logger, "Sending termination signals");
                        terminate_threads();

                        trace!(root_logger, "Joining threads";
                               o!("handles" => format!("{:?}", thread_handles)));
                        for handle in thread_handles {
                            trace!(root_logger, "Joining thread";
                                   o!("handle" => format!("{:?}", handle)));
                            handle.join().expect("Couldn't join thread");
                        }
                        break;
                    }

                    Some(Signal::HUP) => {
                        info!(root_logger, "Received HUP-signal, starting processing";
                              o!("signal" => format!("{:?}", signal)));
                        process()?;
                    }

                    Some(_) => { bail!("got unexpected signal '{:?}'", signal); }
                    None => { bail!("signal was empty"); }
                }
            }
        }
    }

    info!(root_logger, "Application exiting";
          o!("version" => crate_version!(),
             "exited_at" => format!("{}", time::now().rfc3339())));

    Ok(())
}

fn main() {
    // Signals should be set up as early as possible, to set proper signal masks to all threads
    let signal = chan_signal::notify(&[Signal::INT, Signal::TERM, Signal::HUP]);

    let decorator = slog_term::PlainSyncDecorator::new(std::io::stdout());
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let root_logger = Logger::root(drain, o!());

    if let Err(ref e) = run(signal, &root_logger) {
        // Trait that holds `display`
        use error_chain::ChainedError;

        error!(root_logger, "Encountered error";
               o!("error" => format!("{}", e.display())));
    }
}
