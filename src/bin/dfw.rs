// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! # DFW - binary

use bollard::{system::EventsOptions, Docker, API_DEFAULT_VERSION};
use clap::{arg_enum, crate_authors, crate_version, value_t, App, Arg, ArgGroup, ArgMatches};
use crossbeam_channel::{select, Receiver, Sender};
use dfw::{
    process::{ContainerFilter, Process, ProcessContext, ProcessingOptions},
    types::DFW,
    util::*,
};
use failure::bail;
use futures::{future, stream::StreamExt};
use maplit::hashmap;
use slog::{debug, error, info, o, trace, Logger};
use sloggers::{
    terminal::{Destination, TerminalLoggerBuilder},
    types::Severity,
    Build,
};
use std::{
    thread,
    time::{Duration, Instant},
};

mod errors {
    use failure::Error;

    pub type Result<E> = ::std::result::Result<E, Error>;
}

use crate::errors::*;

type Signal = libc::c_int;

arg_enum! {
    #[derive(Debug)]
    enum FirewallBackend {
        Nftables,
        Iptables,
    }
}

arg_enum! {
    #[derive(Debug)]
    enum LoadMode {
        Once,
        Always,
    }
}

fn load_config<B>(matches: &ArgMatches) -> Result<DFW<B>>
where
    B: dfw::FirewallBackend,
    DFW<B>: Process<B>,
{
    let toml: DFW<B> = if matches.is_present("config-file") {
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
            let (s_dummy, r_dummy) = crossbeam_channel::bounded(0);
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
                recv(r_event) -> _ => {
                    trace!(logger, "Received docker event");
                    trigger = Trigger::Event;
                },
                recv(after) -> _ => {
                    trace!(logger, "After timer ran out, sending trigger");
                    trigger = Trigger::After;
                    s_trigger.send(()).expect("Failed to send trigger event");
                }
            }

            trace!(logger, "Resetting after channel";
                   o!("trigger" => format!("{:?}", trigger)));
            match trigger {
                Trigger::Event => {
                    after = crossbeam_channel::after(Duration::from_millis(burst_timeout))
                }
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
            Some(docker_url) => Docker::connect_with_http(&docker_url, 120, API_DEFAULT_VERSION),
            None => Docker::connect_with_unix_defaults(),
        }
        .expect("Failed to setup connection to Docker")
        .negotiate_version()
        .sync()
        .expect("Failed to negotiate version with Docker");
        loop {
            trace!(logger, "Waiting for events");
            docker
                .events(Some(EventsOptions {
                    filters: hashmap! { "type" => vec!["container"] },
                    ..Default::default()
                }))
                .for_each({
                    let logger = logger.clone();
                    let s_event = s_event.clone();
                    move |event| {
                        let event = event.expect("failure in getting Docker event");
                        trace!(logger, "Received event";
                               o!("event" => format!("{:?}", &event)));
                        if let Some(action) = &event.action {
                            match &**action {
                                "create" | "destroy" | "start" | "restart" | "die" | "stop" => {
                                    trace!(logger, "Trigger channel about event";
                                           o!("event" => format!("{:?}", event)));
                                    s_event.send(()).expect("Failed to send trigger event");
                                }
                                _ => {}
                            }
                        }
                        future::ready(())
                    }
                })
                .sync();
        }
    })
}

#[allow(clippy::cognitive_complexity)]
#[cfg(unix)]
fn run<'a, B>(
    matches: &ArgMatches<'a>,
    r_signal: &Receiver<Signal>,
    root_logger: &Logger,
) -> Result<()>
where
    B: std::fmt::Debug + dfw::FirewallBackend,
    DFW<B>: Process<B>,
{
    let toml = load_config(&matches);
    if matches.is_present("check-config") {
        return toml.map(|_| ());
    }

    let toml = toml?;
    debug!(root_logger, "Initial configuration loaded";
           o!("config" => format!("{:#?}", toml)));

    let docker = match matches.value_of("docker-url") {
        Some(docker_url) => Docker::connect_with_http(docker_url, 120, API_DEFAULT_VERSION),
        None => Docker::connect_with_unix_defaults(),
    }?
    .negotiate_version()
    .sync()?;
    // Check if the docker instance is reachable
    trace!(root_logger, "Pinging docker");
    docker.ping().sync()?;

    // Create a dummy channel
    let load_interval = value_t!(matches.value_of("load-interval"), u64)?;
    let load_interval_chan = {
        let load_interval = value_t!(matches.value_of("load-interval"), u64)?;

        if load_interval > 0 {
            // If the load interval is greater than zero, we use a tick-channel
            trace!(root_logger, "Creating tick channel";
                   o!("load_interval" => load_interval));
            crossbeam_channel::tick(Duration::from_secs(load_interval))
        } else {
            // Otherwise we use the dummy channel, which will never send and thus never receive any
            // messages to circumvent having multiple `chan_select!`s below.
            trace!(root_logger, "Creating dummy channel";
                   o!("load_interval" => load_interval));
            let (s_dummy, r_dummy) = crossbeam_channel::bounded(0);
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

    let dry_run = matches.is_present("dry-run");
    trace!(root_logger, "Dry run: {}", dry_run;
           o!("dry_run" => dry_run));

    let processing_logger = root_logger.new(o!());
    let mut process: Box<dyn FnMut() -> Result<()>> =
        match value_t!(matches.value_of("load-mode"), LoadMode)? {
            LoadMode::Once => {
                trace!(root_logger, "Creating process closure according to load mode";
                       o!("load_mode" => "once"));
                Box::new(|| {
                    ProcessContext::new(
                        &docker,
                        &toml,
                        &processing_options,
                        &processing_logger,
                        dry_run,
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
                    ProcessContext::new(
                        &docker,
                        &toml,
                        &processing_options,
                        &processing_logger,
                        dry_run,
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
          "started_at" => time::OffsetDateTime::now_utc().format("%FT%T%z"));

    // Initial processing
    debug!(root_logger, "Start first processing");
    process()?;

    if run_once || (!monitor_events && load_interval == 0) {
        // Either run-once is specified or both events are not monitored and rules aren't processed
        // regularly -- process once, then exit.
        info!(root_logger,
              "Run once specified (or load-interval is zero and events aren't monitored), exiting";
              o!("version" => crate_version!(),
                 "exited_at" => time::OffsetDateTime::now_utc().format("%FT%T%z")));
        return Ok(());
    }

    let event_trigger = if monitor_events {
        // Setup event monitoring
        trace!(root_logger, "Setup event monitoring channel";
               o!("monitor_events" => monitor_events));

        let (s_trigger, r_trigger) = crossbeam_channel::bounded(0);
        let (s_event, r_event) = crossbeam_channel::bounded(0);
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
        let (s_dummy, r_dummy) = crossbeam_channel::bounded(0);
        // Leak the send-channel so that it never gets closed and `recv` never synchronizes.
        ::std::mem::forget(s_dummy);

        r_dummy
    };

    loop {
        select! {
            recv(load_interval_chan) -> _ => {
                info!(root_logger, "Load interval ticked, starting processing");
                process()?;
            },
            recv(event_trigger) -> _ => {
                info!(root_logger, "Received Docker events, starting processing");
                process()?;
            },
            recv(r_signal) -> signal => {
                match signal.expect("received an error instead of a signal") {
                    libc::SIGINT | libc::SIGTERM => {
                        info!(root_logger, "Received kill-signal, exiting";
                              o!("signal" => format!("{:?}", signal)));

                        break;
                    }
                    libc::SIGHUP => {
                        info!(root_logger, "Received HUP-signal, starting processing";
                              o!("signal" => format!("{:?}", signal)));
                        process()?;
                    }
                    _ => { bail!("got unexpected signal '{:?}'", signal); }
                }
            }
        }
    }

    info!(root_logger, "Application exiting";
          o!("version" => crate_version!(),
             "exited_at" => time::OffsetDateTime::now_utc().format("%FT%T%z")));

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
            Arg::with_name("firewall-backend")
                .takes_value(true)
                .long("firewall-backend")
                .value_name("BACKEND")
                .possible_values(
                    FirewallBackend::variants()
                        .iter()
                        .map(|s| s.to_ascii_lowercase())
                        .collect::<Vec<_>>()
                        .iter()
                        .map(|s| &**s)
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .default_value("nftables")
                .case_insensitive(true)
                .help("Select the firewall-backend to use"),
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
                .case_insensitive(true)
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
            Arg::with_name("dry-run")
                .takes_value(false)
                .long("dry-run")
                .help("Don't touch nft, just show what would be done")
                .long_help(
                    "Don't touch nft, just show what would be done. Note that this requires Docker \
                     and the containers/networks referenced in the configuration to be available. \
                     If you want to check the config for validity, specify --check-config instead."
                ),
        )
        .arg(
            Arg::with_name("check-config")
                .takes_value(false)
                .long("check-config")
                .help("Verify if the provided configuration is valid, exit afterwards."),
        )
        .get_matches()
}

fn main() {
    // Parse arguments
    let matches = get_arg_matches();

    // Signals should be set up as early as possible, to set proper signal masks to all threads
    let (s_signal, r_signal) = crossbeam_channel::bounded(10);
    let mut signals =
        signal_hook::iterator::Signals::new(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP])
            .expect("Failed to bind to process signals");
    thread::spawn(move || {
        for signal in signals.forever() {
            s_signal.send(signal).expect("Failed to send signal event");
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

    debug!(root_logger, "Application starting";
           o!("version" => crate_version!(),
              "started_at" => time::OffsetDateTime::now_utc().format("%FT%T%z"),
              "firewall_backend" => matches.value_of("firewall_backend")));
    if let Err(ref e) = match value_t!(matches.value_of("firewall-backend"), FirewallBackend)
        .expect("invalid firewall backend provided")
    {
        FirewallBackend::Nftables => {
            run::<dfw::nftables::Nftables>(&matches, &r_signal, &root_logger)
        }
        FirewallBackend::Iptables => {
            run::<dfw::iptables::Iptables>(&matches, &r_signal, &root_logger)
        }
    } {
        error!(root_logger, "Encountered error";
               o!("error" => format!("{}", e),
                  "backtrace" => format!("{}", e.backtrace())));
    }
}
