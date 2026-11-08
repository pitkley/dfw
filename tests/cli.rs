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

#[test]
fn check_config_validates_nftables_packet_mark() {
    let explicit = r#"external_network_interface = "tailscale0""#;
    let wildcard = r#"external_network_interface = "tailscale*""#;
    let inherited_wildcard = r#"[global_defaults]
external_network_interfaces = ["tailscale*"]"#;
    for (backend, mask, global, interface, error) in [
        ("nftables", "0xff00ffff", "", explicit, None),
        (
            "nftables",
            "0xffffff00",
            "",
            explicit,
            Some("must retain DFW mark bits"),
        ),
        (
            "iptables",
            "0xff00ffff",
            "",
            explicit,
            Some("unknown field `packet_mark`"),
        ),
        (
            "nftables",
            "0xff00ffff",
            "",
            wildcard,
            Some("requires a concrete external interface"),
        ),
        (
            "nftables",
            "0xff00ffff",
            inherited_wildcard,
            "",
            Some("requires a concrete external interface"),
        ),
        (
            "nftables",
            "0xff00ffff",
            "",
            "",
            Some("requires a concrete external interface"),
        ),
    ] {
        let mut config = tempfile::NamedTempFile::new().unwrap();
        write!(
            config,
            r#"{global}
[container_to_wider_world]
default_policy = "drop"

[[container_to_wider_world.rules]]
network = "source-net"
src_container = "source"
{interface}
matches = "tcp dport 443"
verdict = "accept"
backend_options = {{ packet_mark = {{ preserve_mask = {mask}, set_bits = 0x40000 }} }}
"#
        )
        .unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_dfw"))
            .args([
                "--check-config",
                "--firewall-backend",
                backend,
                "--config-file",
            ])
            .arg(config.path())
            .output()
            .unwrap();
        assert_eq!(output.status.success(), error.is_none(), "{output:?}");
        if let Some(error) = error {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(error),
                "{output:?}"
            );
        }
    }
}
