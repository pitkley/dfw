// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! # DFW - binary

use bollard::{
    models::{EventMessage, EventMessageTypeEnum},
    system::EventsOptions,
    Docker, API_DEFAULT_VERSION,
};
use clap::{crate_version, Parser};
use crossbeam_channel::{select, Receiver, Sender};
use dfw::{
    process::{ContainerFilter, Process, ProcessContext, ProcessingOptions},
    types::DFW,
    util::*,
};
use failure::{bail, format_err};
use futures::{pin_mut, TryStreamExt};
use maplit::hashmap;
use slog::{debug, error, info, o, trace, warn, Logger};
use sloggers::{
    terminal::{Destination, TerminalLoggerBuilder},
    types::Severity,
    Build,
};
use std::{fmt, process::ExitCode, thread, time::Duration};
use time::format_description::well_known::Rfc3339;

mod errors {
    use failure::Error;

    pub type Result<E> = ::std::result::Result<E, Error>;
}

use crate::errors::*;

type Signal = libc::c_int;

#[derive(Debug, Clone, clap::ArgEnum)]
enum FirewallBackend {
    Nftables,
    Iptables,
}

impl fmt::Display for FirewallBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
        })
    }
}

#[derive(Debug, Clone, clap::ArgEnum)]
enum LoadMode {
    Once,
    Always,
}

fn container_filter_try_from_str(s: &str) -> Result<ContainerFilter> {
    match &*s.to_ascii_lowercase() {
        "all" => Ok(ContainerFilter::All),
        "running" => Ok(ContainerFilter::Running),
        _ => Err(format_err!("Unknown container filter '{}'", s)),
    }
}

fn load_config<B>(args: &Args) -> Result<DFW<B>>
where
    B: dfw::FirewallBackend,
    DFW<B>: Process<B>,
{
    let toml: DFW<B> = if let Some(ref config_file) = args.config_file {
        load_file(config_file)?
    } else if let Some(ref config_path) = args.config_path {
        load_path(config_path)?
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

    thread::spawn(move || {
        let mut after = crossbeam_channel::never();
        loop {
            select! {
                recv(r_event) -> event => {
                    if event.is_err() {
                        break;
                    }
                    trace!(logger, "Received Docker event");
                    after = crossbeam_channel::after(Duration::from_millis(burst_timeout));
                },
                recv(after) -> _ => {
                    if s_trigger.send(()).is_err() {
                        break;
                    }
                    after = crossbeam_channel::never();
                }
            }
        }
    })
}

fn affects_firewall(event: &EventMessage) -> bool {
    matches!(
        (event.typ, event.action.as_deref()),
        (
            Some(EventMessageTypeEnum::CONTAINER),
            Some("create" | "destroy" | "start" | "restart" | "die" | "stop")
        ) | (
            Some(EventMessageTypeEnum::NETWORK),
            Some("connect" | "disconnect" | "create" | "destroy" | "remove")
        )
    )
}

fn spawn_event_monitor(
    docker_url: Option<String>,
    mut since: String,
    s_event: Sender<()>,
    logger: &Logger,
) -> thread::JoinHandle<()> {
    let logger = logger.new(o!("thread" => "event_monitor"));
    thread::spawn(move || {
        let mut reconnecting = false;
        loop {
            let result = async {
                let docker = match docker_url.as_deref() {
                    Some(url) => Docker::connect_with_http(url, 120, API_DEFAULT_VERSION),
                    None => Docker::connect_with_unix_defaults(),
                }?
                .negotiate_version()
                .await?;

                // A daemon restart can discard its event history. Refresh even if it has no
                // events to replay, and ask for events since before connecting.
                if reconnecting && s_event.send(()).is_err() {
                    return Ok(true);
                }
                let events = docker.events(Some(EventsOptions {
                    since: Some(since.clone()),
                    filters: hashmap! { "type" => vec!["container", "network"] },
                    ..Default::default()
                }));
                pin_mut!(events);
                while let Some(event) = events.try_next().await? {
                    trace!(logger, "Received event"; "event" => format!("{:?}", event));
                    if affects_firewall(&event) && s_event.send(()).is_err() {
                        return Ok(true);
                    }
                }
                Ok::<_, bollard::errors::Error>(false)
            }
            .sync();

            match result {
                Ok(true) => break,
                Ok(false) => warn!(logger, "Docker event stream closed; reconnecting"),
                Err(error) => warn!(logger, "Docker event stream failed; reconnecting";
                                    "error" => error.to_string()),
            }
            reconnecting = true;
            since = time::OffsetDateTime::now_utc().unix_timestamp().to_string();
            thread::sleep(Duration::from_secs(1));
        }
    })
}

#[allow(clippy::cognitive_complexity)]
#[cfg(unix)]
fn run<B>(args: &Args, r_signal: &Receiver<Signal>, root_logger: &Logger) -> Result<()>
where
    B: std::fmt::Debug + dfw::FirewallBackend,
    DFW<B>: Process<B>,
{
    let toml = load_config(args);
    if args.check_config {
        return toml.map(|_| ());
    }

    let toml = toml?;
    debug!(root_logger, "Initial configuration loaded";
           o!("config" => format!("{:#?}", toml)));

    let docker = match args.docker_url {
        Some(ref docker_url) => Docker::connect_with_http(docker_url, 120, API_DEFAULT_VERSION),
        None => Docker::connect_with_unix_defaults(),
    }?
    .negotiate_version()
    .sync()?;
    // Check if the docker instance is reachable
    trace!(root_logger, "Pinging docker");
    docker.ping().sync()?;

    // Create a dummy channel
    let load_interval_chan = {
        let load_interval: u64 = args.load_interval;

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

    let processing_options = ProcessingOptions {
        container_filter: args.container_filter.clone(),
    };

    let monitor_events = !args.disable_event_monitoring;
    trace!(root_logger, "Monitoring events: {}", monitor_events;
           o!("monitor_events" => monitor_events));

    let run_once = args.run_once;
    trace!(root_logger, "Run once: {}", run_once;
           o!("run_once" => run_once));

    let dry_run = args.dry_run;
    trace!(root_logger, "Dry run: {}", dry_run;
           o!("dry_run" => dry_run));

    let processing_logger = root_logger.new(o!());
    let mut process: Box<dyn FnMut() -> Result<()>> = match args.load_mode {
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
            })
        }
        LoadMode::Always => {
            trace!(root_logger, "Creating process closure according to load mode";
                   o!("load_mode" => "always"));
            Box::new(|| {
                let toml = load_config(args)?;
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
            })
        }
    };
    trace!(root_logger, "Load mode: {:?}", args.load_mode);

    info!(root_logger, "Application started";
          "version" => crate_version!(),
          "started_at" => time::OffsetDateTime::now_utc().format(&Rfc3339).expect("failed to format time"));

    // Replay events that arrive while the first snapshot is being processed.
    let events_since = time::OffsetDateTime::now_utc().unix_timestamp().to_string();

    // Initial processing
    debug!(root_logger, "Start first processing");
    process()?;

    if run_once || (!monitor_events && args.load_interval == 0) {
        // Either run-once is specified or both events are not monitored and rules aren't processed
        // regularly -- process once, then exit.
        info!(root_logger,
              "Run once specified (or load-interval is zero and events aren't monitored), exiting";
              o!("version" => crate_version!(),
                 "exited_at" => time::OffsetDateTime::now_utc().format(&Rfc3339).expect("failed to format time")));
        return Ok(());
    }

    let event_trigger = if monitor_events {
        // Setup event monitoring
        trace!(root_logger, "Setup event monitoring channel";
               o!("monitor_events" => monitor_events));

        let (s_trigger, r_trigger) = crossbeam_channel::bounded(0);
        let (s_event, r_event) = crossbeam_channel::bounded(0);
        let docker_url = args.docker_url.as_ref().map(|s| s.to_owned());

        trace!(root_logger, "Start burst monitoring thread";
               o!("burst_timeout" => args.burst_timeout));
        spawn_burst_monitor(args.burst_timeout, s_trigger, r_event, root_logger);

        trace!(root_logger, "Start event monitoring thread";
               o!("docker_url" => &docker_url));
        spawn_event_monitor(docker_url, events_since, s_event, root_logger);

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

    let mut retry = crossbeam_channel::never();
    loop {
        select! {
            recv(load_interval_chan) -> _ => {
                info!(root_logger, "Load interval ticked, starting processing");
            },
            recv(event_trigger) -> trigger => {
                trigger.map_err(|_| format_err!("Docker event monitor stopped"))?;
                info!(root_logger, "Received Docker events, starting processing");
            },
            recv(retry) -> _ => {
                info!(root_logger, "Retrying firewall processing");
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
                    }
                    _ => { bail!("got unexpected signal '{:?}'", signal); }
                }
            }
        }

        retry = match process() {
            Ok(()) => crossbeam_channel::never(),
            Err(error) => {
                warn!(root_logger, "Firewall processing failed; retrying";
                      "error" => error.to_string());
                crossbeam_channel::after(Duration::from_secs(1))
            }
        };
    }

    info!(root_logger, "Application exiting";
          o!("version" => crate_version!(),
             "exited_at" => time::OffsetDateTime::now_utc().format(&Rfc3339).expect("failed to format time")));

    Ok(())
}

#[derive(Debug, Parser)]
#[clap(author, version, about)]
struct Args {
    #[clap(
        long = "log-level",
        value_name = "SEVERITY",
        default_value = "info",
        help = "Define the log level"
    )]
    log_level: Severity,
    #[clap(
        arg_enum,
        long = "firewall-backend",
        value_name = "BACKEND",
        default_value_t = FirewallBackend::Nftables,
        ignore_case = true,
        help = "Select the firewall-backend to use"
    )]
    firewall_backend: FirewallBackend,
    #[clap(
        required_unless_present = "config-path",
        short = 'c',
        long = "config-file",
        value_name = "FILE",
        help = "Set the configuration file"
    )]
    config_file: Option<String>,
    #[clap(
        required_unless_present = "config-file",
        long = "config-path",
        value_name = "PATH",
        help = "Set a path with multiple TOML configuration files"
    )]
    config_path: Option<String>,
    #[clap(
        short = 'd',
        long = "docker-url",
        value_name = "URL",
        help = "Set the URL to the Docker instance (e.g. unix:///tmp/docker.sock)"
    )]
    docker_url: Option<String>,
    #[clap(
        short = 'i',
        long = "load-interval",
        value_name = "INTERVAL",
        default_value_t = 0,
        help = "Interval between rule processing runs, in seconds (0 = disabled)"
    )]
    load_interval: u64,
    #[clap(
        arg_enum,
        short = 'm',
        long = "load-mode",
        value_name = "MODE",
        default_value_t = LoadMode::Once,
        ignore_case = true,
        help = "Define if the config-fields get loaded once, or before every run"
    )]
    load_mode: LoadMode,
    #[clap(
        long = "burst-timeout",
        value_name = "TIMEOUT",
        default_value_t = 500,
        help = "Time to wait after a event was received before processing the rules, in milliseconds"
    )]
    burst_timeout: u64,
    #[clap(
        parse(try_from_str = container_filter_try_from_str),
        long = "container-filter",
        value_name = "FILTER",
        default_value = "running",
        help = "Filter the containers to be included during processing"
    )]
    container_filter: ContainerFilter,
    #[clap(long = "disable-event-monitoring", help = "Disable event monitoring")]
    disable_event_monitoring: bool,
    #[clap(long = "run-once", help = "Process rules once, then exit.")]
    run_once: bool,
    #[clap(
        long = "dry-run",
        help = "Don't touch firewall-rules, just show what would be done",
        long_help = "Don't touch firewall-rules, just show what would be done. Note that this requires Docker and the containers/networks referenced in the configuration to be available. If you want to check the config for validity, specify --check-config instead."
    )]
    dry_run: bool,
    #[clap(
        long = "check-config",
        help = "Verify if the provided configuration is valid, exit afterwards."
    )]
    check_config: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    // Signals should be set up as early as possible, to set proper signal masks to all threads
    let (s_signal, r_signal) = crossbeam_channel::bounded(10);
    let mut signals =
        signal_hook::iterator::Signals::new([libc::SIGINT, libc::SIGTERM, libc::SIGHUP])
            .expect("Failed to bind to process signals");
    thread::spawn(move || {
        for signal in signals.forever() {
            s_signal.send(signal).expect("Failed to send signal event");
        }
    });

    // Setup logging
    let root_logger = TerminalLoggerBuilder::new()
        .format(sloggers::types::Format::Full)
        .level(args.log_level)
        .destination(Destination::Stderr)
        .build()
        .expect("Failed to setup logging");

    debug!(root_logger, "Application starting";
           o!("version" => crate_version!(),
              "started_at" => time::OffsetDateTime::now_utc().format(&Rfc3339).expect("failed to format time"),
              "firewall_backend" => args.firewall_backend.to_string()));
    if let Err(ref e) = match args.firewall_backend {
        FirewallBackend::Nftables => run::<dfw::nftables::Nftables>(&args, &r_signal, &root_logger),
        FirewallBackend::Iptables => run::<dfw::iptables::Iptables>(&args, &r_signal, &root_logger),
    } {
        error!(root_logger, "Encountered error";
               o!("error" => format!("{}", e),
                  "backtrace" => format!("{}", e.backtrace())));
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_monitor_reconnects_and_refreshes_after_invalid_response() {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
        };

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (subscribed, subscription) = crossbeam_channel::bounded(0);
        let server = thread::spawn(move || {
            for (index, body) in [
                r#"{"ApiVersion":"1.43"}"#,
                "invalid JSON\n",
                r#"{"ApiVersion":"1.43"}"#,
                "{\"Type\":\"container\",\"Action\":\"start\"}\n",
            ]
            .into_iter()
            .enumerate()
            {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = BufReader::new(&socket);
                let mut line = String::new();
                request.read_line(&mut line).unwrap();
                if index % 2 == 0 {
                    assert!(line.contains("/version "));
                } else {
                    assert!(line.contains("/events?"));
                    assert!(line.contains("since="));
                }
                loop {
                    line.clear();
                    if request.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                if index == 3 {
                    subscribed.send(()).unwrap();
                }
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });

        let (send_event, events) = crossbeam_channel::bounded(0);
        let logger = Logger::root(slog::Discard, o!());
        let monitor = spawn_event_monitor(Some(url), "1".into(), send_event, &logger);
        events.recv_timeout(Duration::from_secs(5)).unwrap();
        subscription.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(events);
        server.join().unwrap();
        monitor.join().unwrap();
    }

    #[test]
    fn docker_network_changes_trigger_firewall_refresh() {
        for action in ["connect", "disconnect", "create", "destroy", "remove"] {
            assert!(affects_firewall(&EventMessage {
                typ: Some(EventMessageTypeEnum::NETWORK),
                action: Some(action.to_owned()),
                ..Default::default()
            }));
        }
        assert!(!affects_firewall(&EventMessage {
            typ: Some(EventMessageTypeEnum::CONTAINER),
            action: Some("exec_start".to_owned()),
            ..Default::default()
        }));
    }

    #[test]
    fn burst_monitor_exits_when_event_channel_closes() {
        let (send_event, events) = crossbeam_channel::bounded(0);
        let (send_trigger, triggers) = crossbeam_channel::bounded(0);
        let logger = Logger::root(slog::Discard, o!());
        let monitor = spawn_burst_monitor(10, send_trigger, events, &logger);

        send_event.send(()).unwrap();
        triggers.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(send_event);
        assert_eq!(
            triggers.recv_timeout(Duration::from_secs(1)),
            Err(crossbeam_channel::RecvTimeoutError::Disconnected)
        );
        monitor.join().unwrap();
    }
}
