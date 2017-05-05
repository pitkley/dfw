#![cfg(feature = "docker-tests")]

extern crate dfwrs;
extern crate eval;
#[macro_use]
extern crate lazy_static;
extern crate regex;
extern crate shiplift;
#[macro_use]
extern crate slog;

mod common;
mod logs;

use common::*;
use dfwrs::*;
use dfwrs::iptables::IPTablesLogger;
use dfwrs::types::*;
use dfwrs::util::load_file;
use logs::*;
use shiplift::Docker;
use slog::{Drain, Fuse, Logger, OwnedKVList, Record};
use std::panic;
use std::panic::{AssertUnwindSafe, UnwindSafe};
use std::process::Command;

static PROCESSING_OPTIONS: ProcessingOptions =
    ProcessingOptions { container_filter: ContainerFilter::Running };

fn logger() -> Logger {
    struct NoopDrain;
    impl Drain for NoopDrain {
        type Ok = ();
        type Err = ();

        fn log(&self, _record: &Record, _values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
            Ok(())
        }
    }

    let drain = Fuse(NoopDrain);
    let logger = Logger::root(drain, o!());
    logger
}

fn with_compose_environment<F: FnOnce() -> ()>(compose_path: &str, project_name: &str, body: F)
    where F: UnwindSafe
{
    // Create and start environment
    let mut child = Command::new("docker-compose")
        .args(&["--project-name", project_name])
        .args(&["--file", compose_path])
        .args(&["up", "-d"])
        .spawn()
        .expect("failed to setup Docker environment using docker-compose");

    let up_exit_code = child.wait().expect("failed to wait on docker-compose");

    if !up_exit_code.success() {
        panic!("docker-compose did not exit successfully");
    }

    // Run the body, catching any potential panics
    let panic_result = panic::catch_unwind(body);

    // Cleanup started environment
    let mut child = Command::new("docker-compose")
        .args(&["--project-name", project_name])
        .args(&["--file", compose_path])
        .args(&["down", "--volumes"])
        .args(&["--rmi", "local"])
        .spawn()
        .expect("failed to stop Docker environment using docker-compose");

    child.wait().expect("failed to wait on docker-compose");

    // Resume unwinding potential panics
    if let Err(err) = panic_result {
        panic::resume_unwind(err);
    }
}

fn dc_template(num: &str) {
    // Load toml
    let mut s = String::new();
    let toml: DFW = load_file(&resource(&format!("docker/{}/conf.toml", num)).unwrap(),
                              &mut s)
            .unwrap();

    // Setup docker instance
    let docker = Docker::new();
    let ping = docker.ping();

    assert!(ping.is_ok());
    assert_eq!(ping.unwrap().is_empty(), false);

    // `IPTablesLogger` uses a `RefCell` to be able to modify its logging-vector across the
    // lifetime of the struct. `RefCell` is not `UnwindSafe`, so we have to force it to be.
    //
    // This would cause issues if a `panic` would occur within `IPTablesLogger`, but this should
    // not happen.
    let ipt4 = AssertUnwindSafe(IPTablesLogger::new());
    let ipt6 = AssertUnwindSafe(IPTablesLogger::new());

    let logger = logger();

    // Mark `docker` as `UnwindSafe`, since dependent type type `hyper::http::message::Protocol` is
    // not `UnwindSafe`.
    let docker = AssertUnwindSafe(docker);

    with_compose_environment(&resource(&format!("docker/{}/docker-compose.yml", num)).unwrap(),
                             &format!("dfwrs_test_{}", num),
                             || {
        let process = ProcessDFW::new(&docker, &toml, &*ipt4, &*ipt6, &PROCESSING_OPTIONS, &logger)
            .unwrap();

        // Test if container is available
        let containers = docker.containers();
        let container_name = format!("dfwrstest{}_a_1", num);
        let container = containers.get(&container_name);
        let inspect = container.inspect();
        assert!(inspect.is_ok());
        let inspect = inspect.unwrap();
        assert_eq!(inspect.Id.is_empty(), false);

        // Run processing, verify that it succeeded
        let result = process.process();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ());

        // Verify logs for iptables (IPv4)
        let logs4 = ipt4.logs()
            .iter()
            .map(|&(ref f, ref c)| {
                     LogLine {
                         function: f.to_owned(),
                         command: c.to_owned(),
                         regex: false,
                         eval: None,
                     }
                 })
            .collect::<Vec<_>>();
        let expected4 =
            load_log(&resource(&format!("docker/{}/expected-iptables-v4-logs.txt", num)).unwrap());

        // If the logs don't match, include correctly formatted output for comparison.
        if logs4 != expected4 {
            println!("IPv4 logs didn't match");
            println!("----------------------");
            for line in &logs4 {
                println!("{}\t{}", line.function, line.command);
            }
            println!();
        }

        assert_eq!(logs4, expected4);

        // Verify logs for ip6tables (IPv6)
        let logs6 = ipt6.logs()
            .iter()
            .map(|&(ref f, ref c)| {
                     LogLine {
                         function: f.to_owned(),
                         command: c.to_owned(),
                         regex: false,
                         eval: None,
                     }
                 })
            .collect::<Vec<_>>();
        let expected6 =
            load_log(&resource(&format!("docker/{}/expected-iptables-v6-logs.txt", num)).unwrap());

        // If the logs don't match, include correctly formatted output for comparison.
        if logs6 != expected6 {
            println!("IPv6 logs didn't match");
            println!("----------------------");
            for line in &logs6 {
                println!("{}\t{}", line.function, line.command);
            }
            println!();
        }

        assert_eq!(logs6, expected6);
    });
}

#[test]
fn dc_01() {
    dc_template("01");
}

#[test]
fn dc_02() {
    dc_template("02");
}

#[test]
fn dc_03() {
    dc_template("03");
}
