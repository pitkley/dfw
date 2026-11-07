// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

use std::{io::Write, process::Command};

#[test]
fn check_config_returns_failure_for_invalid_toml() {
    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "[invalid").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dfw"))
        .arg("--check-config")
        .arg("--config-file")
        .arg(config.path())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Encountered error"));
}
