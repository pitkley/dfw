// Copyright Pit Kleyersburg <pitkley@googlemail.com>
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
use dfw::iptables::{Iptables, IptablesRuleDiscriminants};
use dfw::nftables::Nftables;
use dfw::process::Process;
use dfw::types::*;
use dfw::util::{load_file, FutureExt};
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

fn test_backend<B: FirewallBackend, F: FnOnce(&DFW<B>, ProcessContext<B>) -> ()>(
    num: &str,
    resource_prefix: &str,
    body: F,
) where
    F: UnwindSafe,
    DFW<B>: Process<B>,
{
    // Load toml
    let toml: DFW<B> =
        load_file(&resource(&format!("docker/{}/{}/conf.toml", resource_prefix, num)).unwrap())
            .unwrap();

    // Create no-op logger
    let logger = logger();

    // Setup docker instance
    let docker = Docker::new();
    let ping = docker.ping().sync();

    assert!(ping.is_ok());
    assert_eq!(ping.unwrap().is_empty(), false);

    // Mark `docker` as `UnwindSafe`, since dependent type type `hyper::http::message::Protocol` is
    // not `UnwindSafe`.
    let docker = AssertUnwindSafe(docker);
    let toml = AssertUnwindSafe(toml);

    with_compose_environment(
        &resource(&format!(
            "docker/{}/{}/docker-compose.yml",
            resource_prefix, num
        ))
        .unwrap(),
        &format!("dfwtest{}", num),
        || {
            let dfw =
                ProcessContext::new(&docker, &toml, &PROCESSING_OPTIONS, &logger, true).unwrap();

            // Test if container is available
            let containers = docker.containers();
            let container_name = format!("dfwtest{}_a_1", num);
            let container = containers.get(&container_name);
            let inspect = container.inspect().sync();
            assert!(inspect.is_ok());
            let inspect = inspect.unwrap();
            assert_eq!(inspect.id.is_empty(), false);

            body(&toml, dfw);
        },
    );
}

fn test_nftables(num: &str) {
    test_backend(num, "nftables", |toml, dfw| {
        // Run processing, verify that it succeeded
        let result = Process::<Nftables>::process(toml, &dfw);
        assert!(result.is_ok());

        let actual = result
            .unwrap()
            .unwrap()
            .iter()
            .map(|nft_command| LogLine {
                command: nft_command.clone(),
                regex: false,
                eval: None,
            })
            .collect::<Vec<_>>();
        let expected = load_loglines(
            &resource(&format!("docker/nftables/{}/expected-nftables.txt", num)).unwrap(),
        );
        compare_loglines(&actual, &expected);
    });
}

fn test_iptables(num: &str) {
    test_backend(num, "iptables", |toml, dfw| {
        // Run processing, verify that it succeeded
        let result = Process::<Iptables>::process(toml, &dfw);
        assert!(result.is_ok());
        let option = result.unwrap();
        assert!(option.is_some());
        let rules = option.unwrap();

        // Verify logs for iptables (IPv4)
        let mut logs4 = Vec::new();
        let rules4 = Iptables::get_rules(rules.clone(), IptablesRuleDiscriminants::V4);
        for rule in rules4 {
            logs4.push(LogLine {
                command: rule,
                regex: false,
                eval: None,
            });
        }
        let expected4 = load_loglines(
            &resource(&format!(
                "docker/iptables/{}/expected-iptables-restore-v4.txt",
                num
            ))
            .unwrap(),
        );
        compare_loglines(&logs4, &expected4);

        // Verify logs for ip6tables (IPv6)
        let mut logs6 = Vec::new();
        let rules6 = Iptables::get_rules(rules, IptablesRuleDiscriminants::V6);
        for rule in rules6 {
            logs6.push(LogLine {
                command: rule,
                regex: false,
                eval: None,
            });
        }
        let expected6 = load_loglines(
            &resource(&format!(
                "docker/iptables/{}/expected-iptables-restore-v6.txt",
                num
            ))
            .unwrap(),
        );
        compare_loglines(&logs6, &expected6);
    });
}

macro_rules! dfw_test {
    ( $name:ident $inner:ident $param:expr) => {
        #[test]
        fn $name() {
            $inner($param);
        }
    };
}

macro_rules! dfw_tests {
    ( $( $name:ident $inner:ident $param:expr );+ $(;)* ) => {
        $( dfw_test!( $name $inner $param ); )+
    }
}

dfw_tests!(
    test_nftables_01 test_nftables "01";
    test_nftables_02 test_nftables "02";
    test_nftables_03 test_nftables "03";
    test_nftables_04 test_nftables "04";
    test_nftables_05 test_nftables "05";
    test_nftables_06 test_nftables "06";

    test_iptables_01 test_iptables "01";
    test_iptables_02 test_iptables "02";
    test_iptables_03 test_iptables "03";
    test_iptables_04 test_iptables "04";
    test_iptables_05 test_iptables "05";
    test_iptables_06 test_iptables "06";
);
