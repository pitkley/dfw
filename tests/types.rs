// Copyright 2017 - 2019 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

#[macro_use]
extern crate maplit;
mod common;

use common::resource;
use dfw::types::*;
use dfw::util::*;

#[test]
fn parse_conf_file() {
    let defaults = Defaults {
        external_network_interfaces: Some(vec!["eni".to_owned()]),
    };
    let initialization = Initialization {
        v4: Some(hashmap! {
            "filter".to_owned() => vec!["-P INPUT ACCEPT".to_owned()],
        }),
        v6: Some(hashmap! {
            "nat".to_owned() => vec!["-P PREROUTING ACCEPT".to_owned()],
        }),
    };
    let container_to_container = ContainerToContainer {
        default_policy: "DROP".to_owned(),
        rules: Some(vec![ContainerToContainerRule {
            network: "network".to_owned(),
            src_container: Some("src_container".to_owned()),
            dst_container: Some("dst_container".to_owned()),
            filter: Some("FILTER".to_owned()),
            action: "ACCEPT".to_owned(),
        }]),
    };
    let container_to_wider_world = ContainerToWiderWorld {
        default_policy: "ACCEPT".to_owned(),
        rules: Some(vec![ContainerToWiderWorldRule {
            network: Some("network".to_owned()),
            src_container: Some("src_container".to_owned()),
            filter: Some("FILTER".to_owned()),
            action: "ACCEPT".to_owned(),
            external_network_interface: Some("eni".to_owned()),
        }]),
    };
    let container_to_host = ContainerToHost {
        default_policy: "ACCEPT".to_owned(),
        rules: Some(vec![ContainerToHostRule {
            network: "network".to_owned(),
            src_container: Some("src_container".to_owned()),
            filter: Some("FILTER".to_owned()),
            action: "ACCEPT".to_owned(),
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
                source_cidr: None,
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
                source_cidr: Some(vec!["192.0.2.1/32".to_owned(), "192.0.2.2/32".to_owned()]),
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

    let expected: DFW = DFW {
        defaults: Some(defaults),
        initialization: Some(initialization),
        container_to_container: Some(container_to_container),
        container_to_wider_world: Some(container_to_wider_world),
        container_to_host: Some(container_to_host),
        wider_world_to_container: Some(wider_world_to_container),
        container_dnat: Some(container_dnat),
    };

    let actual: DFW = load_file(&resource("conf-file.toml").unwrap()).unwrap();

    assert_eq!(expected, actual);
}

#[test]
fn parse_conf_path() {
    let defaults = Defaults {
        external_network_interfaces: Some(vec!["eni".to_owned()]),
    };
    let initialization = Initialization {
        v4: Some(hashmap! {
            "filter".to_owned() => vec!["-P INPUT ACCEPT".to_owned()],
        }),
        v6: Some(hashmap! {
            "nat".to_owned() => vec!["-P PREROUTING ACCEPT".to_owned()],
        }),
    };
    let container_to_container = ContainerToContainer {
        default_policy: "DROP".to_owned(),
        rules: Some(vec![ContainerToContainerRule {
            network: "network".to_owned(),
            src_container: Some("src_container".to_owned()),
            dst_container: Some("dst_container".to_owned()),
            filter: Some("FILTER".to_owned()),
            action: "ACCEPT".to_owned(),
        }]),
    };
    let container_to_wider_world = ContainerToWiderWorld {
        default_policy: "ACCEPT".to_owned(),
        rules: Some(vec![ContainerToWiderWorldRule {
            network: Some("network".to_owned()),
            src_container: Some("src_container".to_owned()),
            filter: Some("FILTER".to_owned()),
            action: "ACCEPT".to_owned(),
            external_network_interface: Some("eni".to_owned()),
        }]),
    };
    let container_to_host = ContainerToHost {
        default_policy: "ACCEPT".to_owned(),
        rules: Some(vec![ContainerToHostRule {
            network: "network".to_owned(),
            src_container: Some("src_container".to_owned()),
            filter: Some("FILTER".to_owned()),
            action: "ACCEPT".to_owned(),
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
                source_cidr: None,
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
                source_cidr: Some(vec!["192.0.2.1/32".to_owned(), "192.0.2.2/32".to_owned()]),
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

    let expected: DFW = DFW {
        defaults: Some(defaults),
        initialization: Some(initialization),
        container_to_container: Some(container_to_container),
        container_to_wider_world: Some(container_to_wider_world),
        container_to_host: Some(container_to_host),
        wider_world_to_container: Some(wider_world_to_container),
        container_dnat: Some(container_dnat),
    };

    let actual: DFW = load_path(&resource("conf_path").unwrap()).unwrap();

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
        source_cidr: None,
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
        source_cidr: None,
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
            source_cidr: None,
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
        source_cidr: None,
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
            source_cidr: None,
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
        source_cidr: None,
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

    let expected = Defaults {
        external_network_interfaces: Some(vec!["eni".to_owned()]),
    };
    let actual: Defaults = toml::from_str(fragment).unwrap();

    assert_eq!(expected, actual);
}

#[test]
fn parse_external_network_interfaces_seq() {
    let fragment = r#"external_network_interfaces = ["eni1", "eni2"]"#;

    let expected = Defaults {
        external_network_interfaces: Some(vec!["eni1".to_owned(), "eni2".to_owned()]),
    };
    let actual: Defaults = toml::from_str(fragment).unwrap();

    assert_eq!(expected, actual);
}
