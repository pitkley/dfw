#![cfg(feature = "docker-tests")]

extern crate dfwrs;
extern crate shiplift;

use dfwrs::*;
use shiplift::Docker;
use std::panic;
use std::panic::{AssertUnwindSafe, UnwindSafe};
use std::path::PathBuf;
use std::process::Command;

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
    let docker = Docker::new();
    let ping = docker.ping();

    assert!(ping.is_ok());
    assert_eq!(ping.unwrap().is_empty(), false);

    let docker = AssertUnwindSafe(docker);

    with_compose_environment(&resource("docker/01/docker-compose.yml").unwrap(),
                             "dfwrs_test_01",
                             || {
        let containers = docker.containers();
        let container = containers.get("dfwrstest01_a_1");
        let inspect = container.inspect();

        assert!(inspect.is_ok());
        let inspect = inspect.unwrap();

        assert_eq!(inspect.Id.is_empty(), false);
    });
}
