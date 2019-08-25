// Copyright 2017, 2018 Pit Kleyersburg <pitkley@googlemail.com>
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
use std::process::{Command, Output};

macro_rules! proxy {
    ( $( #[$attr:meta] )* $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty ) => {
        $( #[$attr] )*
        fn $name(&self $(, $param: $ty )*) -> Result<$ret, Error> {
            (self.0).$name($($param),+).map_err(Into::into)
        }
    };
}

macro_rules! proxies {
    ( $( $( #[$attr:meta] )*
         $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty );+ $(;)* ) => {
        $( proxy!( $( #[$attr] )* $name ( $( $param : $ty ),* ) -> $ret ); )+
    };
}

macro_rules! dummy {
    ( $( #[$attr:meta] )* $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty ) => {
        $( #[$attr] )*
        #[allow(unused_variables)]
        fn $name(&self $(, $param: $ty )*) -> Result<$ret, Error> {
            Ok(Default::default())
        }
    };
}

macro_rules! dummies {
    ( $( $( #[$attr:meta] )*
         $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty );+ $(;)* ) => {
        $( dummy!( $( #[$attr] )* $name ( $( $param : $ty ),* ) -> $ret ); )+
    };
}

struct IPTablesRestoreProxy(IPTablesRestore);
impl IPTables for IPTablesRestoreProxy {
    proxies! {
        get_policy(table: &str, chain: &str) -> String;
        set_policy(table: &str, chain: &str, policy: &str) -> bool;
        execute(table: &str, command: &str) -> Output;
        exists(table: &str, chain: &str, rule: &str) -> bool;
        chain_exists(table: &str, chain: &str) -> bool;
        insert(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        insert_unique(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        replace(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        append(table: &str, chain: &str, rule: &str) -> bool;
        append_unique(table: &str, chain: &str, rule: &str) -> bool;
        append_replace(table: &str, chain: &str, rule: &str) -> bool;
        delete(table: &str, chain: &str, rule: &str) -> bool;
        delete_all(table: &str, chain: &str, rule: &str) -> bool;
        list(table: &str, chain: &str) -> Vec<String>;
        list_table(table: &str) -> Vec<String>;
        list_chains(table: &str) -> Vec<String>;
        new_chain(table: &str, chain: &str) -> bool;
        flush_chain(table: &str, chain: &str) -> bool;
        rename_chain(table: &str, old_chain: &str, new_chain: &str) -> bool;
        delete_chain(table: &str, chain: &str) -> bool;
        flush_table(table: &str) -> bool;
    }

    dummies! {
        commit() -> bool;
    }
}

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
        println!("LogLines didn't match");
        println!("---------------------");
        for line in actual {
            println!("{}\t{:?}", line.function, line.command);
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

fn dc_template<F: FnOnce(&I, &I) -> (), I: IPTables>(
    num: &str,
    ipt4: AssertUnwindSafe<I>,
    ipt6: AssertUnwindSafe<I>,
    body: F,
) where
    F: UnwindSafe,
{
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
            // TODO: only start environment once, then test both IPTablesLogger and IPTablesRestore
            let process =
                ProcessDFW::new(&docker, &toml, &*ipt4, &*ipt6, &PROCESSING_OPTIONS, &logger)
                    .unwrap();

            // Test if container is available
            let containers = docker.containers();
            let container_name = format!("dfwtest{}_a_1", num);
            let container = containers.get(&container_name);
            let inspect = container.inspect();
            assert!(inspect.is_ok());
            let inspect = inspect.unwrap();
            assert_eq!(inspect.Id.is_empty(), false);

            // Run processing, verify that it succeeded
            let result = process.process();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ());

            body(&ipt4, &ipt6);
        },
    );
}

fn test_iptables_restore(num: &str) {
    // `IPTablesLogger` uses a `RefCell` to be able to modify its logging-vector across the
    // lifetime of the struct. `RefCell` is not `UnwindSafe`, so we have to force it to be.
    //
    // This would cause issues if a `panic` would occur within `IPTablesLogger`, but this should
    // not happen.
    let ipt4 = AssertUnwindSafe(IPTablesRestoreProxy(
        IPTablesRestore::new(IPVersion::IPv4).unwrap(),
    ));
    let ipt6 = AssertUnwindSafe(IPTablesRestoreProxy(
        IPTablesRestore::new(IPVersion::IPv6).unwrap(),
    ));

    dc_template(num, ipt4, ipt6, |ref ipt4, ref ipt6| {
        // Verify logs for iptables (IPv4)
        let logs4 = ipt4
            .0
            .get_rules()
            .iter()
            .map(|c| LogLine {
                function: "-".to_owned(),
                command: Some(c.to_owned()),
                regex: false,
                eval: None,
            })
            .collect::<Vec<_>>();
        let expected4 = load_loglines(
            &resource(&format!("docker/{}/expected-iptables-restore-v4.txt", num)).unwrap(),
        );

        compare_loglines(&logs4, &expected4);

        // Verify logs for ip6tables (IPv6)
        let logs6 = ipt6
            .0
            .get_rules()
            .iter()
            .map(|c| LogLine {
                function: "-".to_owned(),
                command: Some(c.to_owned()),
                regex: false,
                eval: None,
            })
            .collect::<Vec<_>>();
        let expected6 = load_loglines(
            &resource(&format!("docker/{}/expected-iptables-restore-v6.txt", num)).unwrap(),
        );

        compare_loglines(&logs6, &expected6);
    });
}

fn test_iptables_logger(num: &str) {
    // `IPTablesLogger` uses a `RefCell` to be able to modify its logging-vector across the
    // lifetime of the struct. `RefCell` is not `UnwindSafe`, so we have to force it to be.
    //
    // This would cause issues if a `panic` would occur within `IPTablesLogger`, but this should
    // not happen.
    let ipt4 = AssertUnwindSafe(IPTablesLogger::new());
    let ipt6 = AssertUnwindSafe(IPTablesLogger::new());

    dc_template(num, ipt4, ipt6, |ref ipt4, ref ipt6| {
        // Verify logs for iptables (IPv4)
        let logs4 = ipt4
            .logs()
            .iter()
            .map(|&(ref f, ref c)| LogLine {
                function: f.to_owned(),
                command: c.clone(),
                regex: false,
                eval: None,
            })
            .collect::<Vec<_>>();
        let expected4 = load_loglines(
            &resource(&format!("docker/{}/expected-iptables-v4-logs.txt", num)).unwrap(),
        );

        compare_loglines(&logs4, &expected4);

        // Verify logs for ip6tables (IPv6)
        let logs6 = ipt6
            .logs()
            .iter()
            .map(|&(ref f, ref c)| LogLine {
                function: f.to_owned(),
                command: c.clone(),
                regex: false,
                eval: None,
            })
            .collect::<Vec<_>>();
        let expected6 = load_loglines(
            &resource(&format!("docker/{}/expected-iptables-v6-logs.txt", num)).unwrap(),
        );

        compare_loglines(&logs6, &expected6);
    });
}

#[test]
fn test_iptables_logger_01() {
    test_iptables_logger("01");
}

#[test]
fn test_iptables_logger_02() {
    test_iptables_logger("02");
}

#[test]
fn test_iptables_logger_03() {
    test_iptables_logger("03");
}

#[test]
fn test_iptables_logger_04() {
    test_iptables_logger("04");
}

#[test]
fn test_iptables_logger_05() {
    test_iptables_logger("05");
}

#[test]
fn test_iptables_logger_06() {
    test_iptables_logger("06");
}

#[test]
fn test_iptables_restore_01() {
    test_iptables_restore("01");
}

#[test]
fn test_iptables_restore_02() {
    test_iptables_restore("02");
}

#[test]
fn test_iptables_restore_03() {
    test_iptables_restore("03");
}

#[test]
fn test_iptables_restore_04() {
    test_iptables_restore("04");
}

#[test]
fn test_iptables_restore_05() {
    test_iptables_restore("05");
}

#[test]
fn test_iptables_restore_06() {
    test_iptables_restore("06");
}
