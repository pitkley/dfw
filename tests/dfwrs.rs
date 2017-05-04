#![cfg(feature = "docker-tests")]

extern crate dfwrs;
extern crate eval;
extern crate regex;
extern crate shiplift;
#[macro_use]
extern crate slog;

use dfwrs::*;
use dfwrs::iptables::IPTablesLogger;
use dfwrs::types::*;
use dfwrs::util::load_file;
use regex::Regex;
use shiplift::Docker;
use slog::{Drain, Fuse, Logger, OwnedKVList, Record};
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use std::panic;
use std::panic::{AssertUnwindSafe, UnwindSafe};
use std::path::PathBuf;
use std::process::Command;

static PROCESSING_OPTIONS: ProcessingOptions =
    ProcessingOptions { container_filter: ContainerFilter::Running };

#[derive(Debug)]
struct LogLine {
    function: String,
    regex: bool,
    command: String,
    eval: Option<String>,
}

impl PartialEq for LogLine {
    fn eq(&self, other: &LogLine) -> bool {
        // If `function` is unequal, we don't have to do further comparisons
        if self.function != other.function {
            return false;
        }

        if self.regex {
            if other.regex {
                // Both are regex, not equal by our definition.
                return false;
            }

            // Handle regex
            let re = Regex::new(&self.command).unwrap();

            // Verify we have a match
            if !re.is_match(&other.command) {
                return false;
            }

            // Check if we have to have constraints to evaluate
            if let Some(ref eval) = self.eval {
                // Get capture groups
                let captures = re.captures(&other.command).unwrap();

                // Try to expand the capture groups used in the eval-string
                let mut expansion = String::new();
                captures.expand(&eval, &mut expansion);

                // Evaluate the string
                let e = eval::eval(&expansion);
                return e.is_ok() && e.unwrap() == eval::to_value(true);
            } else {
                // Nothing to evaluate, `is_match` was successful.
                return true;
            }
        } else {
            if other.regex {
                // We don't want to duplicate the regex handling, just ask `other` for the result.
                return other.eq(self);
            } else {
                // No regex involved, just `command` left to compare
                return self.command == other.command;
            }
        }
    }
}

impl Eq for LogLine {}

fn load_log(log_path: &str) -> Vec<LogLine> {
    let file = BufReader::new(File::open(log_path).unwrap());
    let mut v = Vec::new();

    for line in file.lines() {
        if line.is_err() {
            continue;
        }
        let line = line.unwrap();

        let s = line.split("\t").collect::<Vec<_>>();
        v.push(match s.len() {
                   2 => {
                       LogLine {
                           function: s[0].to_owned(),
                           command: s[1].to_owned(),
                           regex: false,
                           eval: None,
                       }
                   }
                   3 => {
                       LogLine {
                           function: s[0].to_owned(),
                           command: s[1].to_owned(),
                           regex: true,
                           eval: Some(s[2].to_owned()),
                       }
                   }
                   _ => panic!("log line split incorrectly"),
               });
    }

    v
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
        assert_eq!(logs6, expected6);
    });
}

#[test]
fn dc_01() {
    dc_template("01");
}
