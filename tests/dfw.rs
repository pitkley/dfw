// Copyright 2017 - 2019 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

#![cfg(feature = "docker-tests")]

mod common;
mod logs;

use common::*;
use dfw::types::*;
use dfw::util::load_file;
use dfw::*;
use itertools::{EitherOrBoth, Itertools};
use logs::*;
use shiplift::Docker;
use slog::{o, Drain, Fuse, Logger, OwnedKVList, Record};
use std::panic;
use std::panic::{AssertUnwindSafe, UnwindSafe};
use std::process::Command;

static PROCESSING_OPTIONS: ProcessingOptions = ProcessingOptions {
    container_filter: ContainerFilter::Running,
};

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

fn compare_loglines(actual: &Vec<LogLine>, expected: &Vec<LogLine>) {
    // If the logs don't match, include correctly formatted output for comparison.
    if actual != expected {
        let width = expected
            .iter()
            .map(|expected| expected.command.len())
            .max()
            .unwrap_or_default();
        println!("LogLines didn't match (expected -- actual)");
        println!("---------------------");
        for either in expected.iter().zip_longest(actual) {
            match either {
                EitherOrBoth::Both(expected, actual) => println!(
                    "{:<width$} {}",
                    expected.command,
                    actual.command,
                    width = width,
                ),
                EitherOrBoth::Left(expected) => {
                    println!("{:<width$} -", expected.command, width = width)
                }
                EitherOrBoth::Right(actual) => {
                    println!("{:<width$} {}", "-", actual.command, width = width)
                }
            }
        }
        println!();
    }

    assert_eq!(actual, expected);
}

fn with_compose_environment<F: FnOnce() -> ()>(compose_path: &str, project_name: &str, body: F)
where
    F: UnwindSafe,
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

fn test_nftables(num: &str) {
    // Load toml
    let toml: DFW = load_file(&resource(&format!("docker/{}/conf.toml", num)).unwrap()).unwrap();

    // Create no-op logger
    let logger = logger();

    // Setup docker instance
    let docker = Docker::new();
    let ping = docker.ping();

    assert!(ping.is_ok());
    assert_eq!(ping.unwrap().is_empty(), false);

    // Mark `docker` as `UnwindSafe`, since dependent type type `hyper::http::message::Protocol` is
    // not `UnwindSafe`.
    let docker = AssertUnwindSafe(docker);

    with_compose_environment(
        &resource(&format!("docker/{}/docker-compose.yml", num)).unwrap(),
        &format!("dfwtest{}", num),
        || {
            let toml2 = toml.clone();
            let dfw =
                ProcessContext::new(&docker, &toml2, &PROCESSING_OPTIONS, &logger, true).unwrap();

            // Test if container is available
            let containers = docker.containers();
            let container_name = format!("dfwtest{}_a_1", num);
            let container = containers.get(&container_name);
            let inspect = container.inspect();
            assert!(inspect.is_ok());
            let inspect = inspect.unwrap();
            assert_eq!(inspect.Id.is_empty(), false);

            // Run processing, verify that it succeeded
            let result = toml.process(&dfw);
            assert!(result.is_ok());

            let actual = result
                .unwrap()
                .unwrap()
                .iter()
                .map(|nft_command| LogLine {
                    command: nft_command.to_owned(),
                    regex: false,
                    eval: None,
                })
                .collect::<Vec<_>>();
            let expected =
                load_loglines(&resource(&format!("docker/{}/expected-nftables.txt", num)).unwrap());
            compare_loglines(&actual, &expected);
        },
    );
}

#[test]
fn test_nftables_01() {
    test_nftables("01");
}

#[test]
fn test_nftables_02() {
    test_nftables("02");
}

#[test]
fn test_nftables_03() {
    test_nftables("03");
}

#[test]
fn test_nftables_04() {
    test_nftables("04");
}

#[test]
fn test_nftables_05() {
    test_nftables("05");
}

#[test]
fn test_nftables_06() {
    test_nftables("06");
}
