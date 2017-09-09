// Copyright 2017 Pit Kleyersburg <pitkley@googlemail.com>
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
extern crate chan;
extern crate chan_signal;
#[macro_use]
extern crate clap;
extern crate dfw;
#[macro_use]
extern crate error_chain;
extern crate iptables as ipt;
extern crate libc;
extern crate serde;
extern crate shiplift;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;
extern crate time;
extern crate url;

use chan::{Receiver, Sender};
use chan_signal::Signal;
use clap::{App, Arg, ArgGroup, ArgMatches};
use dfw::{ContainerFilter, ProcessDFW, ProcessingOptions};
use dfw::iptables::{IPTables, IPTablesDummy, IPTablesProxy};
use dfw::types::DFW;
use dfw::util::*;
use shiplift::Docker;
use shiplift::builder::{EventFilter, EventFilterType, EventsOptions};
use slog::{Logger, Drain};
use std::ascii::AsciiExt;
use std::os::unix::thread::JoinHandleExt;
use std::thread;
use std::time::Duration;

mod errors {
    error_chain! {
        links {
            Dfw(::dfw::errors::Error, ::dfw::errors::ErrorKind);
        }

        foreign_links {
            ClapError(::clap::Error);
            Docker(::shiplift::errors::Error);
            IPTError(::ipt::error::IPTError);
            UrlParseError(::url::ParseError);
        }
    }
}

use errors::*;

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
fn run(signal: &Receiver<Signal>, root_logger: &Logger) -> Result<()> {
    info!(root_logger, "Application starting";
          o!("version" => crate_version!(),
             "started_at" => format!("{}", time::now().rfc3339())));

    trace!(root_logger, "Parsing command line arguments");
    let matches = App::new("dfw")
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
        .arg(Arg::with_name("container-filter")
                 .takes_value(true)
                 .long("container-filter")
                 .value_name("FILTER")
                 .possible_values(&["all", "running"])
                 .default_value("running")
                 .help("Filter the containers to be included during processing"))
        .arg(Arg::with_name("disable-event-monitoring")
                 .takes_value(false)
                 .long("disable-event-monitoring")
                 .help("Disable Docker event monitoring"))
        .arg(Arg::with_name("run-once")
                 .takes_value(false)
                 .long("run-once")
                 .help("Process rules once, then exit."))
        .arg(Arg::with_name("dry-run")
                 .takes_value(false)
                 .long("dry-run")
                 .help("Don't touch iptables, just show what would be done"))
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

    let container_filter = match matches.value_of("container-filter") {
        Some("all") => ContainerFilter::All,
        Some("running") => ContainerFilter::Running,
        Some(_) | None => bail!("wrong or no container filter specified"),
    };
    let processing_options = ProcessingOptions { container_filter: container_filter };

    let monitor_events = !matches.is_present("disable-event-monitoring");
    trace!(root_logger, "Monitoring events: {}", monitor_events;
           o!("monitor_events" => monitor_events));

    let run_once = matches.is_present("run-once");
    trace!(root_logger, "Run once: {}", run_once;
           o!("run_once" => run_once));

    let dry_run = matches.is_present("dry-run");
    trace!(root_logger, "Dry run: {}", dry_run;
           o!("dry_run" => dry_run));

    let toml = load_config(&matches)?;
    info!(root_logger, "Initial configuration loaded");
    debug!(root_logger, "Loaded config: {:#?}", toml);

    let (ipt4_dry_run, ipt6_dry_run) = (IPTablesDummy, IPTablesDummy);
    let (ipt4_ipt, ipt6_ipt) = (IPTablesProxy(ipt::new(false)?), IPTablesProxy(ipt::new(true)?));
    let ipt4: &IPTables = if dry_run { &ipt4_dry_run } else { &ipt4_ipt };
    let ipt6: &IPTables = if dry_run { &ipt6_dry_run } else { &ipt6_ipt };

    let process: Box<Fn() -> Result<()>> = match value_t!(matches.value_of("load-mode"),
                                                          LoadMode)? {
        LoadMode::Once => {
            trace!(root_logger, "Creating process closure according to load mode";
                   o!("load_mode" => "once"));
            Box::new(|| {
                ProcessDFW::new(&docker, &toml, ipt4, ipt6, &processing_options, root_logger)?
                    .process()
                    .map_err(From::from)
            })
        }
        LoadMode::Always => {
            trace!(root_logger, "Creating process closure according to load mode";
                   o!("load_mode" => "always"));
            Box::new(|| {
                let toml = load_config(&matches)?;
                info!(root_logger, "Reloaded configuration before processing");
                debug!(root_logger, "Reloaded config: {:#?}", toml);

                ProcessDFW::new(&docker, &toml, ipt4, ipt6, &processing_options, root_logger)?
                    .process()
                    .map_err(From::from)
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

    if run_once || (!monitor_events && load_interval == 0) {
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
        let burst_handle =
            spawn_burst_monitor(burst_timeout, s_trigger, r_event, r_burst_exit, root_logger);

        trace!(root_logger, "Start event monitoring thread";
               o!("docker_url" => &docker_url));
        let event_handle = spawn_event_monitor(docker_url, s_event, root_logger);
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

    if let Err(ref e) = run(&signal, &root_logger) {
        // Trait that holds `display`
        use error_chain::ChainedError;

        error!(root_logger, "Encountered error";
               o!("error" => format!("{}", e.display())));
    }
}
