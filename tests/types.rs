// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

mod common;

use common::resource;
use dfw::{
    process::{Process, ProcessContext},
    types::*,
    util::*,
    FirewallBackend,
};
use serde::Deserialize;

#[derive(Debug, Eq, PartialEq)]
struct TestBackend;
impl FirewallBackend for TestBackend
where
    DFW<Self>: Process<Self>,
{
    type Rule = String;
    type Defaults = TestBackendDefaults;

    fn apply(_rules: Vec<Self::Rule>, _ctx: &ProcessContext<Self>) -> dfw::errors::Result<()> {
        unimplemented!()
    }
}

impl Process<TestBackend> for DFW<TestBackend> {
    fn process(
        &self,
        _ctx: &ProcessContext<TestBackend>,
    ) -> Result<Option<Vec<String>>, failure::Error> {
        unimplemented!()
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct TestBackendDefaults {
    test: String,
}

#[test]
fn parse_conf_file() {
    let global_defaults = GlobalDefaults {
        external_network_interfaces: Some(vec!["eni".to_owned()]),
        default_docker_bridge_to_host_policy: ChainPolicy::Accept,
        ..Default::default()
    };
    let backend_defaults = TestBackendDefaults {
        test: "custom backend defaults".to_owned(),
    };
    let container_to_container = ContainerToContainer {
        default_policy: ChainPolicy::Drop,
        rules: Some(vec![ContainerToContainerRule {
            network: "network".to_owned(),
            src_container: Some("src_container".to_owned()),
            dst_container: Some("dst_container".to_owned()),
            matches: Some("FILTER".to_owned()),
            verdict: RuleVerdict::Accept,
        }]),
    };
    let container_to_wider_world = ContainerToWiderWorld {
        default_policy: RuleVerdict::Accept,
        rules: Some(vec![ContainerToWiderWorldRule {
            network: Some("network".to_owned()),
            src_container: Some("src_container".to_owned()),
            matches: Some("FILTER".to_owned()),
            verdict: RuleVerdict::Accept,
            external_network_interface: Some("eni".to_owned()),
        }]),
    };
    let container_to_host = ContainerToHost {
        default_policy: RuleVerdict::Accept,
        rules: Some(vec![ContainerToHostRule {
            network: "network".to_owned(),
            src_container: Some("src_container".to_owned()),
            matches: Some("FILTER".to_owned()),
            verdict: RuleVerdict::Accept,
        }]),
    };
    let wider_world_to_container = WiderWorldToContainer {
        rules: Some(vec![
            WiderWorldToContainerRule {
                network: "network".to_owned(),
                dst_container: "dst_container".to_owned(),
                expose_port: vec![ExposePort {
                    host_port: 80,
                    container_port: None,
                    family: "tcp".to_owned(),
                }],
                external_network_interface: Some("eni".to_owned()),
                expose_via_ipv6: false,
                source_cidr_v4: None,
                source_cidr_v6: None,
            },
            WiderWorldToContainerRule {
                network: "network".to_owned(),
                dst_container: "dst_container".to_owned(),
                expose_port: vec![ExposePort {
                    host_port: 22,
                    container_port: None,
                    family: "tcp".to_owned(),
                }],
                external_network_interface: Some("eni".to_owned()),
                expose_via_ipv6: true,
                source_cidr_v4: Some(vec!["192.0.2.1/32".to_owned(), "192.0.2.2/32".to_owned()]),
                source_cidr_v6: Some(vec![
                    "2001:db8::1/128".to_owned(),
                    "2001:db8::2/128".to_owned(),
                ]),
            },
        ]),
    };
    let container_dnat = ContainerDNAT {
        rules: Some(vec![ContainerDNATRule {
            src_network: Some("src_network".to_owned()),
            src_container: Some("src_container".to_owned()),
            dst_network: "dst_network".to_owned(),
            dst_container: "dst_container".to_owned(),
            expose_port: vec![ExposePort {
                host_port: 80,
                container_port: None,
                family: "tcp".to_owned(),
            }],
        }]),
    };

    let expected: DFW<TestBackend> = DFW {
        global_defaults,
        backend_defaults: Some(backend_defaults),
        container_to_container: Some(container_to_container),
        container_to_wider_world: Some(container_to_wider_world),
        container_to_host: Some(container_to_host),
        wider_world_to_container: Some(wider_world_to_container),
        container_dnat: Some(container_dnat),
    };

    let actual = load_file(&resource("conf-file.toml").unwrap()).unwrap();

    assert_eq!(expected, actual);
}

#[test]
fn parse_conf_path() {
    let global_defaults = GlobalDefaults {
        external_network_interfaces: Some(vec!["eni".to_owned()]),
        default_docker_bridge_to_host_policy: ChainPolicy::Accept,
        ..Default::default()
    };
    let backend_defaults = TestBackendDefaults {
        test: "custom backend defaults".to_owned(),
    };
    let container_to_container = ContainerToContainer {
        default_policy: ChainPolicy::Drop,
        rules: Some(vec![ContainerToContainerRule {
            network: "network".to_owned(),
            src_container: Some("src_container".to_owned()),
            dst_container: Some("dst_container".to_owned()),
            matches: Some("FILTER".to_owned()),
            verdict: RuleVerdict::Accept,
        }]),
    };
    let container_to_wider_world = ContainerToWiderWorld {
        default_policy: RuleVerdict::Accept,
        rules: Some(vec![ContainerToWiderWorldRule {
            network: Some("network".to_owned()),
            src_container: Some("src_container".to_owned()),
            matches: Some("FILTER".to_owned()),
            verdict: RuleVerdict::Accept,
            external_network_interface: Some("eni".to_owned()),
        }]),
    };
    let container_to_host = ContainerToHost {
        default_policy: RuleVerdict::Accept,
        rules: Some(vec![ContainerToHostRule {
            network: "network".to_owned(),
            src_container: Some("src_container".to_owned()),
            matches: Some("FILTER".to_owned()),
            verdict: RuleVerdict::Accept,
        }]),
    };
    let wider_world_to_container = WiderWorldToContainer {
        rules: Some(vec![
            WiderWorldToContainerRule {
                network: "network".to_owned(),
                dst_container: "dst_container".to_owned(),
                expose_port: vec![ExposePort {
                    host_port: 80,
                    container_port: None,
                    family: "tcp".to_owned(),
                }],
                external_network_interface: Some("eni".to_owned()),
                expose_via_ipv6: false,
                source_cidr_v4: None,
                source_cidr_v6: None,
            },
            WiderWorldToContainerRule {
                network: "network".to_owned(),
                dst_container: "dst_container".to_owned(),
                expose_port: vec![ExposePort {
                    host_port: 22,
                    container_port: None,
                    family: "tcp".to_owned(),
                }],
                external_network_interface: Some("eni".to_owned()),
                expose_via_ipv6: true,
                source_cidr_v4: Some(vec!["192.0.2.1/32".to_owned(), "192.0.2.2/32".to_owned()]),
                source_cidr_v6: Some(vec![
                    "2001:db8::1/128".to_owned(),
                    "2001:db8::2/128".to_owned(),
                ]),
            },
        ]),
    };
    let container_dnat = ContainerDNAT {
        rules: Some(vec![ContainerDNATRule {
            src_network: Some("src_network".to_owned()),
            src_container: Some("src_container".to_owned()),
            dst_network: "dst_network".to_owned(),
            dst_container: "dst_container".to_owned(),
            expose_port: vec![ExposePort {
                host_port: 80,
                container_port: None,
                family: "tcp".to_owned(),
            }],
        }]),
    };

    let expected: DFW<TestBackend> = DFW {
        global_defaults,
        backend_defaults: Some(backend_defaults),
        container_to_container: Some(container_to_container),
        container_to_wider_world: Some(container_to_wider_world),
        container_to_host: Some(container_to_host),
        wider_world_to_container: Some(wider_world_to_container),
        container_dnat: Some(container_dnat),
    };

    let actual = load_path(&resource("conf_path").unwrap()).unwrap();

    assert_eq!(expected, actual);
}

#[test]
fn parse_expose_port_single_int() {
    let fragment = r#"
        network = "network"
        dst_container = "dst_container"
        expose_port = 80
        "#;

    let expected = WiderWorldToContainerRule {
        network: "network".to_owned(),
        dst_container: "dst_container".to_owned(),
        expose_port: vec![ExposePort {
            host_port: 80,
            container_port: None,
            family: "tcp".to_owned(),
        }],
        external_network_interface: None,
        expose_via_ipv6: true,
        source_cidr_v4: None,
        source_cidr_v6: None,
    };
    let actual: WiderWorldToContainerRule = toml::from_str(fragment).unwrap();

    assert_eq!(expected, actual);
}

#[test]
fn parse_expose_port_seq_int() {
    let fragment = r#"
        network = "network"
        dst_container = "dst_container"
        expose_port = [80, 81]
        "#;

    let expected = WiderWorldToContainerRule {
        network: "network".to_owned(),
        dst_container: "dst_container".to_owned(),
        expose_port: vec![
            ExposePort {
                host_port: 80,
                container_port: None,
                family: "tcp".to_owned(),
            },
            ExposePort {
                host_port: 81,
                container_port: None,
                family: "tcp".to_owned(),
            },
        ],
        external_network_interface: None,
        expose_via_ipv6: true,
        source_cidr_v4: None,
        source_cidr_v6: None,
    };
    let actual: WiderWorldToContainerRule = toml::from_str(fragment).unwrap();

    assert_eq!(expected, actual);
}

#[test]
fn parse_expose_port_single_string() {
    for &(port, family) in &[(80, "tcp"), (53, "udp"), (1234, "other")] {
        let fragment = format!(
            r#"
            network = "network"
            dst_container = "dst_container"
            expose_port = "{}/{}"
            "#,
            port, family
        );

        let expected = WiderWorldToContainerRule {
            network: "network".to_owned(),
            dst_container: "dst_container".to_owned(),
            expose_port: vec![ExposePort {
                host_port: port.to_owned(),
                container_port: None,
                family: family.to_owned(),
            }],
            external_network_interface: None,
            expose_via_ipv6: true,
            source_cidr_v4: None,
            source_cidr_v6: None,
        };
        let actual: WiderWorldToContainerRule = toml::from_str(&fragment).unwrap();

        assert_eq!(expected, actual);
    }
}

#[test]
fn parse_expose_port_seq_string() {
    let fragment = r#"
        network = "network"
        dst_container = "dst_container"
        expose_port = ["80/tcp", "53/udp", "1234/other"]
        "#;

    let expected = WiderWorldToContainerRule {
        network: "network".to_owned(),
        dst_container: "dst_container".to_owned(),
        expose_port: vec![
            ExposePort {
                host_port: 80,
                container_port: None,
                family: "tcp".to_owned(),
            },
            ExposePort {
                host_port: 53,
                container_port: None,
                family: "udp".to_owned(),
            },
            ExposePort {
                host_port: 1234,
                container_port: None,
                family: "other".to_owned(),
            },
        ],
        external_network_interface: None,
        expose_via_ipv6: true,
        source_cidr_v4: None,
        source_cidr_v6: None,
    };
    let actual: WiderWorldToContainerRule = toml::from_str(fragment).unwrap();

    assert_eq!(expected, actual);
}

#[test]
fn parse_expose_port_single_struct() {
    for port in &[
        "{ host_port = 80 }",
        r#"{ host_port = 80, family = "tcp" }"#,
    ] {
        let fragment = format!(
            r#"
            network = "network"
            dst_container = "dst_container"
            expose_port = {}
            "#,
            port
        );

        let expected = WiderWorldToContainerRule {
            network: "network".to_owned(),
            dst_container: "dst_container".to_owned(),
            expose_port: vec![ExposePort {
                host_port: 80,
                container_port: None,
                family: "tcp".to_owned(),
            }],
            external_network_interface: None,
            expose_via_ipv6: true,
            source_cidr_v4: None,
            source_cidr_v6: None,
        };
        let actual: WiderWorldToContainerRule = toml::from_str(&fragment).unwrap();

        assert_eq!(expected, actual);
    }
}

#[test]
fn parse_expose_port_seq_struct() {
    let fragment = r#"
        network = "network"
        dst_container = "dst_container"
        expose_port = [
            { host_port = 80 },
            { host_port = 8080, container_port = 80 },
            { host_port = 8081, container_port = 81, family = "udp" },
            { host_port = 8082, container_port = 82, family = "other" },
        ]
        "#;

    let expected = WiderWorldToContainerRule {
        network: "network".to_owned(),
        dst_container: "dst_container".to_owned(),
        expose_port: vec![
            ExposePort {
                host_port: 80,
                container_port: None,
                family: "tcp".to_owned(),
            },
            ExposePort {
                host_port: 8080,
                container_port: Some(80),
                family: "tcp".to_owned(),
            },
            ExposePort {
                host_port: 8081,
                container_port: Some(81),
                family: "udp".to_owned(),
            },
            ExposePort {
                host_port: 8082,
                container_port: Some(82),
                family: "other".to_owned(),
            },
        ],
        external_network_interface: None,
        expose_via_ipv6: true,
        source_cidr_v4: None,
        source_cidr_v6: None,
    };
    let actual: WiderWorldToContainerRule = toml::from_str(fragment).unwrap();

    assert_eq!(expected, actual);
}

#[test]
#[should_panic(expected = "port string has invalid format")]
fn parse_expose_port_string_invalid_format() {
    let fragment = r#"
        network = "network"
        dst_container = "dst_container"
        expose_port = "80/tcp/what"
        "#;

    toml::from_str::<WiderWorldToContainerRule>(fragment).unwrap();
}

#[test]
#[should_panic(expected = "invalid digit found in string")]
fn parse_expose_port_string_invalid_int() {
    let fragment = r#"
        network = "network"
        dst_container = "dst_container"
        expose_port = "noint"
        "#;

    toml::from_str::<WiderWorldToContainerRule>(fragment).unwrap();
}

#[test]
#[should_panic(expected = "invalid digit found in string")]
fn parse_expose_port_string_invalid_int2() {
    let fragment = r#"
        network = "network"
        dst_container = "dst_container"
        expose_port = "noint/tcp"
        "#;

    toml::from_str::<WiderWorldToContainerRule>(fragment).unwrap();
}

#[test]
fn parse_external_network_interfaces_single() {
    let fragment = r#"external_network_interfaces = "eni""#;

    let expected = GlobalDefaults {
        external_network_interfaces: Some(vec!["eni".to_owned()]),
        default_docker_bridge_to_host_policy: ChainPolicy::Accept,
        ..Default::default()
    };
    let actual: GlobalDefaults = toml::from_str(fragment).unwrap();

    assert_eq!(expected, actual);
}

#[test]
fn parse_external_network_interfaces_seq() {
    let fragment = r#"external_network_interfaces = ["eni1", "eni2"]"#;

    let expected = GlobalDefaults {
        external_network_interfaces: Some(vec!["eni1".to_owned(), "eni2".to_owned()]),
        default_docker_bridge_to_host_policy: ChainPolicy::Accept,
        ..Default::default()
    };
    let actual: GlobalDefaults = toml::from_str(fragment).unwrap();

    assert_eq!(expected, actual);
}

/// These tests verify that certain features or configuration fields are available within the same
/// major version. Additionally these tests are configured to fail if the major version is bumped,
/// which ensures that we will be reminded to remove them and the deprecated items.
#[cfg_attr(crate_major_version = "1", allow(deprecated))]
#[cfg_attr(not(crate_major_version = "1"), should_panic)]
#[test]
fn ensure_backwards_compatibility_v1() {
    // `defaults` needs to be valid in addition to `global_defaults`
    toml::from_str::<DFW<TestBackend>>(
        r#"
        [defaults]
        default_docker_bridge_to_host_policy = "accept"
        "#,
    )
    .unwrap();

    // `initialization` needs to be valid in addition to `backend_defaults`
    toml::from_str::<DFW<TestBackend>>(
        r#"
        [initialization]
        test = "custom backend defaults"
        "#,
    )
    .unwrap();

    // `action` needs to be valid in addition to `verdict`.
    toml::from_str::<DFW<TestBackend>>(
        r#"
        [container_to_container]
        default_policy = "accept"
        [[container_to_container.rules]]
        network = ""
        action = "accept"

        [container_to_wider_world]
        default_policy = "accept"
        [[container_to_wider_world.rules]]
        action = "accept"

        [container_to_host]
        default_policy = "accept"
        [[container_to_host.rules]]
        network = ""
        action = "accept"
        "#,
    )
    .unwrap();

    // `source_cidr` needs to be valid in addition to `source_cidr_v4`.
    {
        let dfw = toml::from_str::<DFW<TestBackend>>(
            r#"
        [[wider_world_to_container.rules]]
        network = ""
        dst_container = ""
        expose_port = 0
        source_cidr = "127.0.0.0/8"
        "#,
        )
        .unwrap();
        let rules = dfw.wider_world_to_container.unwrap().rules.unwrap();
        let WiderWorldToContainerRule {
            source_cidr_v4,
            source_cidr_v6,
            ..
        } = rules.get(0).unwrap();
        assert!(source_cidr_v4.is_some());
        assert!(source_cidr_v6.is_none());
    }

    // GlobalDefaults::custom_tables needs to be present.
    let _ = GlobalDefaults {
        custom_tables: None,
        ..Default::default()
    };

    // nftables::types::Defaults::rules needs to be present.
    let _ = dfw::nftables::types::Defaults {
        rules: None,
        ..Default::default()
    };
}
