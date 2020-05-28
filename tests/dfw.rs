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
use dfw::{
    iptables::{Iptables, IptablesRuleDiscriminants},
    nftables::Nftables,
    process::{ContainerFilter, Process, ProcessContext, ProcessingOptions},
    types::*,
    util::FutureExt,
    FirewallBackend,
};
use itertools::{EitherOrBoth, Itertools};
use logs::*;
use paste;
use serde::de::DeserializeOwned;
use shiplift::Docker;
use slog::{o, Drain, Fuse, Logger, OwnedKVList, Record};
use std::{
    fs::File,
    io::{prelude::*, BufReader},
    panic::{self, AssertUnwindSafe, UnwindSafe},
    process::Command,
};

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

fn load_config_and_inject_project_name<T>(
    files: &[&str],
    project_name: &str,
) -> Result<T, failure::Error>
where
    T: DeserializeOwned,
{
    let mut contents = String::new();
    for file in files {
        let mut file = BufReader::new(File::open(file)?);
        file.read_to_string(&mut contents)?;
    }
    let contents = contents.replace("PROJECT_", &format!("{}_", project_name));
    Ok(toml::from_str(&contents)?)
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
    path: &str,
    resource_prefix: &str,
    body: F,
) where
    F: UnwindSafe,
    DFW<B>: Process<B>,
{
    // Load toml
    let project_name = format!(
        "dfwtest{}",
        path.chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>(),
    );
    let toml: DFW<B> = load_config_and_inject_project_name(
        &[
            &resource(&format!("docker/{}/conf.toml", path)).unwrap(),
            &resource(&format!("docker/{}/{}/conf.toml", path, resource_prefix)).unwrap(),
        ],
        &project_name,
    )
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
        &resource(&format!("docker/{}/docker-compose.yml", path)).unwrap(),
        &project_name,
        || {
            let dfw =
                ProcessContext::new(&docker, &toml, &PROCESSING_OPTIONS, &logger, true).unwrap();

            // Test if container is available
            let containers = docker.containers();
            let container_name = format!("{}_a_1", project_name);
            let container = containers.get(&container_name);
            let inspect = container.inspect().sync();
            assert!(inspect.is_ok());
            let inspect = inspect.unwrap();
            assert_eq!(inspect.id.is_empty(), false);

            body(&toml, dfw);
        },
    );
}

fn test_nftables(path: &str) {
    test_backend(path, "nftables", |toml, dfw| {
        // Run processing, verify that it succeeded
        let result = Process::<Nftables>::process(toml, &dfw);

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
            &resource(&format!("docker/{}/nftables/expected-nftables.txt", path)).unwrap(),
        );
        compare_loglines(&actual, &expected);
    });
}

fn test_nftables_process_should_fail(path: &str) {
    test_backend(path, "nftables", |toml, dfw| {
        // Run processing, verify that it succeeded
        let result = Process::<Nftables>::process(toml, &dfw);
        assert!(result.is_err());
    });
}

fn test_iptables(path: &str) {
    test_backend(path, "iptables", |toml, dfw| {
        // Run processing, verify that it succeeded
        let rules = Process::<Iptables>::process(toml, &dfw).unwrap().unwrap();

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
                "docker/{}/iptables/expected-iptables-v4.txt",
                path
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
                "docker/{}/iptables/expected-iptables-v6.txt",
                path
            ))
            .unwrap(),
        );
        compare_loglines(&logs6, &expected6);
    });
}

fn test_iptables_process_should_fail(path: &str) {
    test_backend(path, "iptables", |toml, dfw| {
        // Run processing, verify that it succeeded
        let result = Process::<Iptables>::process(toml, &dfw);
        assert!(result.is_err());
    });
}

macro_rules! dfw_test {
    ( R F $backend:ident $name:tt $param:expr $(;)* ) => {
        paste::item! {
            #[test]
            fn [<regressiontest_ $backend _ $name>]() {
                [<test_ $backend _process_should_fail>](concat!("_regression-tests/", $param));
            }
        }
    };
    ( R F $backend:ident $param:expr $(;)* ) => {
        paste::item! {
            #[test]
            fn [<regressiontest_ $backend _ $param>]() {
                [<test_ $backend _process_should_fail>](concat!("_regression-tests/", $param));
            }
        }
    };
    ( R $backend:ident $name:tt $param:expr $(;)* ) => {
        paste::item! {
            #[test]
            fn [<regressiontest_ $backend _ $name>]() {
                [<test_ $backend>](concat!("_regression-tests/", $param));
            }
        }
    };
    ( R $backend:ident $param:expr $(;)* ) => {
        paste::item! {
            #[test]
            fn [<regressiontest_ $backend _ $param>]() {
                [<test_ $backend>](concat!("_regression-tests/", $param));
            }
        }
    };
    ( F $backend:ident $param:expr $(;)* ) => {
        paste::item! {
            #[test]
            fn [<test_ $backend _ $param>]() {
                [<test_ $backend _process_should_fail>]($param);
            }
        }
    };
    ( $backend:ident $param:expr $(;)* ) => {
        paste::item! {
            #[test]
            fn [<test_ $backend _ $param>]() {
                [<test_ $backend>]($param);
            }
        }
    };
}
macro_rules! dfw_tests {
    // If the remaining token-tree starts with a comma, ignore it and continue parsing the tail.
    ( @internal ; $($tail:tt)* ) => {
        dfw_tests!( @internal $($tail)*);
    };
    // If the remaining token-tree starts with a semicolon, ignore it and continue parsing the tail.
    ( @internal , $($tail:tt)* ) => {
        dfw_tests!( @internal $($tail)*);
    };
    // If the starting tokens are in the form `R F <tt> <tt>`, we reference a regression test that
    // should fail (and have a certain name).
    ( @internal R F $name:tt $param:tt $($tail:tt)* ) => {
        dfw_test!( R F nftables $name $param );
        dfw_test!( R F iptables $name $param );
        dfw_tests!( @internal $($tail)* );
    };
    // If the starting tokens are in the form `R F <tt>`, we reference a regression test that should
    // fail.
    ( @internal R F $param:tt $($tail:tt)* ) => {
        dfw_test!( R F nftables $param );
        dfw_test!( R F iptables $param );
        dfw_tests!( @internal $($tail)* );
    };
    // If the starting tokens are in the form `R <tt> <tt>`, we reference a regression test (with a
    // certain name).
    ( @internal R $name:tt $param:tt $($tail:tt)* ) => {
        dfw_test!( R nftables $name $param );
        dfw_test!( R iptables $name $param );
        dfw_tests!( @internal $($tail)* );
    };
    // If the starting tokens are in the form `R <tt>`, we reference a regression test.
    ( @internal R $param:tt $($tail:tt)* ) => {
        dfw_test!( R nftables $param );
        dfw_test!( R iptables $param );
        dfw_tests!( @internal $($tail)* );
    };
    // If the starting tokens are in the form `F <tt>`, we reference a regular test that should
    // fail.
    ( @internal F $param:tt $($tail:tt)* ) => {
        dfw_test!( F nftables $param );
        dfw_test!( F iptables $param );
        dfw_tests!( @internal $($tail)* );
    };
    // If the starting token is simply a `<tt>`, the previous rules didn't match and the have a
    // regular test.
    ( @internal $param:tt $($tail:tt)* ) => {
        dfw_test!( nftables $param );
        dfw_test!( iptables $param );
        dfw_tests!( @internal $($tail)* );
    };
    // This rule matches once all tokens have been consumed.
    ( @internal ) => {
    };
    // Start-rule.
    ( $($tts:tt)* ) => {
        dfw_tests!( @internal $($tts)* );
    };
}

dfw_tests!(
    "01";
    "02";
    "03";
    "04";
    "05";
    "06";
    "07";

    R F "001_gh_166_01" "001-gh-166/01";
    R F "001_gh_166_02" "001-gh-166/02";
    R F "001_gh_166_03" "001-gh-166/03";
    R "001_gh_166_04" "001-gh-166/04";
);
