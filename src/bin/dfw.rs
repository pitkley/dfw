// Copyright 2017, 2018 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! # DFW - binary

// Increase the compiler's recursion limit for the `error_chain` crate.
#![recursion_limit = "1024"]

// Import external libraries

#[macro_use]
extern crate crossbeam_channel as channel;
#[macro_use]
extern crate clap;
extern crate dfw;
#[macro_use]
extern crate failure;
extern crate iptables as ipt;
extern crate libc;
extern crate shiplift;
extern crate signal_hook;
#[macro_use]
extern crate slog;
extern crate sloggers;
extern crate time;
extern crate url;

use channel::{Receiver, Sender};
use clap::{App, Arg, ArgGroup, ArgMatches};
use dfw::iptables::{IPTables, IPTablesDummy, IPTablesRestore, IPVersion};
use dfw::types::DFW;
use dfw::util::*;
use dfw::{ContainerFilter, ProcessDFW, ProcessingOptions};
use shiplift::builder::{EventFilter, EventFilterType, EventsOptions};
use shiplift::Docker;
use slog::Logger;
use sloggers::terminal::{Destination, TerminalLoggerBuilder};
use sloggers::types::Severity;
use sloggers::Build;
#[allow(unused_imports, deprecated)]
use std::ascii::AsciiExt;
use std::thread;
use std::time::{Duration, Instant};

mod errors {
    use failure::Error;

    pub type Result<E> = ::std::result::Result<E, Error>;
}

use errors::*;

type Signal = libc::c_int;

arg_enum! {
    #[derive(Debug)]
    enum IPTablesBackend {
        IPTables,
        IPTablesRestore,
        IPTablesDummy
    }
}

arg_enum! {
    #[derive(Debug)]
    enum LoadMode {
        Once,
        Always
    }
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

fn spawn_burst_monitor(
    burst_timeout: u64,
    s_trigger: Sender<()>,
    r_event: Receiver<()>,
    logger: &Logger,
) -> thread::JoinHandle<()> {
    let logger = logger.new(o!("thread" => "burst_monitor"));

    #[derive(Debug)]
    enum Trigger {
        Event,
        After,
        None,
    }
    thread::spawn(move || {
        let dummy: Receiver<Instant> = {
            let (s_dummy, r_dummy) = channel::bounded(0);
            // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
            ::std::mem::forget(s_dummy);
            r_dummy
        };
        let mut after: Receiver<Instant> = dummy.clone();

        loop {
            // The `unused_assignments` warning for the following variable is wrong, since
            // `trigger` is read at the match-statement.
            // Maybe related to:
            //   https://github.com/rust-lang/rfcs/issues/1710
            #[allow(unused_assignments)]
            let mut trigger: Trigger = Trigger::None;

            select! {
                recv(r_event) => {
                    trace!(logger, "Received docker event");
                    trigger = Trigger::Event;
                },
                recv(after) => {
                    trace!(logger, "After timer ran out, sending trigger");
                    trigger = Trigger::After;
                    s_trigger.send(());
                }
            }

            trace!(logger, "Resetting after channel";
                   o!("trigger" => format!("{:?}", trigger)));
            match trigger {
                Trigger::Event => after = channel::after(Duration::from_millis(burst_timeout)),
                Trigger::After => after = dummy.clone(),
                Trigger::None => {}
            }
        }
    })
}

fn spawn_event_monitor(
    docker_url: Option<String>,
    s_event: Sender<()>,
    logger: &Logger,
) -> thread::JoinHandle<()> {
    let logger = logger.new(o!("thread" => "event_monitor"));

    thread::spawn(move || {
        let docker = match docker_url {
            Some(docker_url) => Docker::host(docker_url.parse().unwrap()),
            None => Docker::new(),
        };
        loop {
            trace!(logger, "Waiting for events");
            for event in docker
                .events(
                    &EventsOptions::builder()
                        .filter(vec![EventFilter::Type(EventFilterType::Container)])
                        .build(),
                )
                .unwrap()
            {
                trace!(logger, "Received event";
                       o!("event" => format!("{:?}", &event)));
                match event.status {
                    Some(ref status) => match &**status {
                        "create" | "destroy" | "start" | "restart" | "die" | "stop" => {
                            trace!(logger, "Trigger channel about event";
                                       o!("event" => format!("{:?}", event)));
                            s_event.send(());
                            break;
                        }
                        _ => continue,
                    },
                    None => continue,
                }
            }
        }
    })
}

#[cfg(unix)]
fn run<'a>(
    matches: &ArgMatches<'a>,
    r_signal: &Receiver<Signal>,
    root_logger: &Logger,
) -> Result<()> {
    debug!(root_logger, "Application starting";
           o!("version" => crate_version!(),
              "started_at" => format!("{}", time::now().rfc3339())));

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
            channel::tick(Duration::from_secs(load_interval))
        } else {
            // Otherwise we use the dummy channel, which will never send and thus never receive any
            // messages to circumvent having multiple `chan_select!`s below.
            trace!(root_logger, "Creating dummy channel";
                   o!("load_interval" => load_interval));
            let (s_dummy, r_dummy) = channel::bounded(0);
            // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
            ::std::mem::forget(s_dummy);

            r_dummy
        }
    };

    let container_filter = match matches.value_of("container-filter") {
        Some("all") => ContainerFilter::All,
        Some("running") => ContainerFilter::Running,
        Some(_) | None => bail!("wrong or no container filter specified"),
    };
    let processing_options = ProcessingOptions { container_filter };

    let monitor_events = !matches.is_present("disable-event-monitoring");
    trace!(root_logger, "Monitoring events: {}", monitor_events;
           o!("monitor_events" => monitor_events));

    let run_once = matches.is_present("run-once");
    trace!(root_logger, "Run once: {}", run_once;
           o!("run_once" => run_once));

    let toml = load_config(&matches)?;
    debug!(root_logger, "Initial configuration loaded";
           o!("config" => format!("{:#?}", toml)));

    let dry_run = matches.is_present("dry-run");
    let iptables_backend = value_t!(matches.value_of("iptables-backend"), IPTablesBackend)?;
    trace!(root_logger, "Dry run: {}", dry_run;
           o!("dry_run" => dry_run));

    let (ipt4, ipt6): (Box<IPTables>, Box<IPTables>) = if dry_run {
        (Box::new(IPTablesDummy), Box::new(IPTablesDummy))
    } else {
        match iptables_backend {
            IPTablesBackend::IPTables => (Box::new(ipt::new(false)?), Box::new(ipt::new(true)?)),
            IPTablesBackend::IPTablesRestore => (
                Box::new(IPTablesRestore::new(IPVersion::IPv4)?),
                Box::new(IPTablesRestore::new(IPVersion::IPv6)?),
            ),
            IPTablesBackend::IPTablesDummy => (Box::new(IPTablesDummy), Box::new(IPTablesDummy)),
        }
    };

    let processing_logger = root_logger.new(o!());
    let process: Box<Fn() -> Result<()>> = match value_t!(matches.value_of("load-mode"), LoadMode)?
    {
        LoadMode::Once => {
            trace!(root_logger, "Creating process closure according to load mode";
                   o!("load_mode" => "once"));
            Box::new(|| {
                ProcessDFW::new(
                    &docker,
                    &toml,
                    &*ipt4,
                    &*ipt6,
                    &processing_options,
                    &processing_logger,
                )?
                .process()
                .map_err(From::from)
            })
        }
        LoadMode::Always => {
            trace!(root_logger, "Creating process closure according to load mode";
                   o!("load_mode" => "always"));
            Box::new(|| {
                let toml = load_config(&matches)?;
                debug!(root_logger, "Reloaded configuration before processing";
                       o!("config" => format!("{:#?}", toml)));

                ProcessDFW::new(
                    &docker,
                    &toml,
                    &*ipt4,
                    &*ipt6,
                    &processing_options,
                    &processing_logger,
                )?
                .process()
                .map_err(From::from)
            })
        }
    };
    trace!(
        root_logger,
        "Load mode: {:?}",
        matches.value_of("load-mode")
    );

    info!(root_logger, "Application started";
          "version" => crate_version!(),
          "started_at" => format!("{}", time::now().rfc3339()));

    // Initial processing
    debug!(root_logger, "Start first processing");
    process()?;

    if run_once || (!monitor_events && load_interval == 0) {
        // Either run-once is specified or both events are not monitored and rules aren't processed
        // regularly -- process once, then exit.
        info!(root_logger,
              "Run once specified (or load-interval is zero and events aren't monitored), exiting";
              o!("version" => crate_version!(),
                 "exited_at" => format!("{}", time::now().rfc3339())));
        ::std::process::exit(0);
    }

    let event_trigger = if monitor_events {
        // Setup event monitoring
        trace!(root_logger, "Setup event monitoring channel";
               o!("monitor_events" => monitor_events));

        let (s_trigger, r_trigger) = channel::bounded(0);
        let (s_event, r_event) = channel::bounded(0);
        let docker_url = matches.value_of("docker-url").map(|s| s.to_owned());
        let burst_timeout = value_t!(matches.value_of("burst-timeout"), u64)?;

        trace!(root_logger, "Start burst monitoring thread";
               o!("burst_timeout" => burst_timeout));
        spawn_burst_monitor(burst_timeout, s_trigger, r_event, root_logger);

        trace!(root_logger, "Start event monitoring thread";
               o!("docker_url" => &docker_url));
        spawn_event_monitor(docker_url, s_event, root_logger);

        // Note: we need both spawned threads for the entirety of the programs lifetime. As such we
        // do not bother cleaning them up, but rather let the OS handle the cleanup once we exit the
        // main process.

        r_trigger
    } else {
        trace!(root_logger, "Creating dummy channel";
               o!("monitor_events" => monitor_events));
        let (s_dummy, r_dummy) = channel::bounded(0);
        // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
        ::std::mem::forget(s_dummy);

        r_dummy
    };

    loop {
        select! {
            recv(load_interval_chan) => {
                info!(root_logger, "Load interval ticked, starting processing");
                process()?;
            },
            recv(event_trigger) => {
                info!(root_logger, "Received Docker events, starting processing");
                process()?;
            },
            recv(r_signal, signal) => {
                match signal {
                    Some(libc::SIGINT) | Some(libc::SIGTERM) => {
                        info!(root_logger, "Received kill-signal, exiting";
                              o!("signal" => format!("{:?}", signal)));

                        break;
                    }

                    Some(libc::SIGHUP) => {
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

fn get_arg_matches<'a>() -> ArgMatches<'a> {
    App::new("dfw")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Docker Firewall Framework, in Rust")
        .arg(
            Arg::with_name("log-level")
                .takes_value(true)
                .long("log-level")
                .value_name("SEVERITY")
                .possible_values(&["trace", "debug", "info", "warning", "error", "critical"])
                .default_value("info")
                .help("Define the log level"),
        )
        .arg(
            Arg::with_name("config-file")
                .takes_value(true)
                .short("c")
                .long("config-file")
                .value_name("FILE")
                .help("Set the configuration file"),
        )
        .arg(
            Arg::with_name("config-path")
                .takes_value(true)
                .long("config-path")
                .value_name("PATH")
                .help("Set a path with multiple TOML configuration files"),
        )
        .group(
            ArgGroup::with_name("config")
                .args(&["config-file", "config-path"])
                .multiple(false)
                .required(true),
        )
        .arg(
            Arg::with_name("docker-url")
                .takes_value(true)
                .short("d")
                .long("docker-url")
                .value_name("URL")
                .help("Set the url to the Docker instance (e.g. unix:///tmp/docker.sock)"),
        )
        .arg(
            Arg::with_name("load-interval")
                .takes_value(true)
                .default_value("0")
                .short("i")
                .long("load-interval")
                .value_name("INTERVAL")
                .help("Interval between rule processing runs, in seconds (0 = disabled)"),
        )
        .arg(
            Arg::with_name("load-mode")
                .takes_value(true)
                .short("m")
                .long("load-mode")
                .value_name("MODE")
                .possible_values(
                    LoadMode::variants()
                        .iter()
                        .map(|s| s.to_ascii_lowercase())
                        .collect::<Vec<_>>()
                        .iter()
                        .map(|s| &**s)
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .default_value("once")
                .help("Define if the config-files get loaded once, or before every run"),
        )
        .arg(
            Arg::with_name("burst-timeout")
                .takes_value(true)
                .default_value("500")
                .long("burst-timeout")
                .value_name("TIMEOUT")
                .help(
                    "Time to wait after a event was received before processing the rules, in \
                     milliseconds",
                ),
        )
        .arg(
            Arg::with_name("container-filter")
                .takes_value(true)
                .long("container-filter")
                .value_name("FILTER")
                .possible_values(&["all", "running"])
                .default_value("running")
                .help("Filter the containers to be included during processing"),
        )
        .arg(
            Arg::with_name("disable-event-monitoring")
                .takes_value(false)
                .long("disable-event-monitoring")
                .help("Disable Docker event monitoring"),
        )
        .arg(
            Arg::with_name("run-once")
                .takes_value(false)
                .long("run-once")
                .help("Process rules once, then exit."),
        )
        .arg(
            Arg::with_name("iptables-backend")
                .takes_value(true)
                .long("iptables-backend")
                .value_name("BACKEND")
                .possible_values(
                    IPTablesBackend::variants()
                        .iter()
                        .map(|s| s.to_ascii_lowercase())
                        .collect::<Vec<_>>()
                        .iter()
                        .map(|s| &**s)
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .default_value("iptables")
                .help("Choose the iptables backend to use"),
        )
        .arg(
            Arg::with_name("dry-run")
                .takes_value(false)
                .long("dry-run")
                .help("Don't touch iptables, just show what would be done"),
        )
        .get_matches()
}
fn main() {
    // Parse arguments
    let matches = get_arg_matches();

    // Signals should be set up as early as possible, to set proper signal masks to all threads
    let (s_signal, r_signal) = channel::bounded(10);
    let signals = signal_hook::iterator::Signals::new(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP])
        .expect("Failed to bind to process signals");
    thread::spawn(move || {
        for signal in signals.forever() {
            s_signal.send(signal);
        }
    });

    // Setup logging
    let log_level =
        value_t!(matches.value_of("log-level"), Severity).expect("Unknown severity specified");
    let root_logger = TerminalLoggerBuilder::new()
        .format(sloggers::types::Format::Full)
        .level(log_level)
        .destination(Destination::Stderr)
        .build()
        .expect("Failed to setup logging");

    if let Err(ref e) = run(&matches, &r_signal, &root_logger) {
        error!(root_logger, "Encountered error";
               o!("error" => format!("{}", e)));
    }
}
