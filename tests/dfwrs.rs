#![cfg(feature = "docker-tests")]

extern crate dfwrs;
extern crate shiplift;
#[macro_use]
extern crate slog;

use dfwrs::*;
use dfwrs::iptables::IPTablesLogger;
use dfwrs::types::*;
use dfwrs::util::load_file;
use shiplift::Docker;
use slog::{Drain, Fuse, Logger, OwnedKVList, Record};
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::panic;
use std::panic::{AssertUnwindSafe, UnwindSafe};
use std::path::PathBuf;
use std::process::Command;

fn load_log(log_path: &str) -> Vec<(String, String)> {
    let file = BufReader::new(File::open(log_path).unwrap());

    file.lines()
        .into_iter()
        .filter(Result::is_ok)
        .map(Result::unwrap)
        .map(|e| {
                 let mut s = e.splitn(2, ' ');
                 (s.next().unwrap().trim().to_owned(), s.next().unwrap().trim().to_owned())
             })
        .collect::<Vec<_>>()
}

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

fn resource(segment: &str) -> Option<String> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("resources/test");
    p.push(segment);

    p.to_str().map(|s| s.to_owned())
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

#[test]
fn dc_01() {
    // Load toml
    let mut s = String::new();
    let toml: DFW = load_file(&resource("docker/01/conf.toml").unwrap(), &mut s).unwrap();

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

    with_compose_environment(&resource("docker/01/docker-compose.yml").unwrap(),
                             "dfwrs_test_01",
                             || {
        let process = ProcessDFW::new(&docker, &toml, &*ipt4, &*ipt6, &logger).unwrap();

        // Test if container is available
        let containers = docker.containers();
        let container = containers.get("dfwrstest01_a_1");
        let inspect = container.inspect();
        assert!(inspect.is_ok());
        let inspect = inspect.unwrap();
        assert_eq!(inspect.Id.is_empty(), false);

        // Run processing, verify that it succeeded
        let result = process.process();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ());

        // Verify logs for iptables (IPv4)
        let logs4 = ipt4.logs();
        let expected4 = load_log(&resource("docker/01/expected-iptables-v4-logs.txt").unwrap());
        assert_eq!(logs4, expected4);

        // Verify logs for ip6tables (IPv6)
        let logs6 = ipt6.logs();
        let expected6 = load_log(&resource("docker/01/expected-iptables-v6-logs.txt").unwrap());
        assert_eq!(logs6, expected6);
    });
}
