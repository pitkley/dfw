// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! The types in this module make up the structure of the configuration-file(s).
//!
//! # Example
//!
//! The following is an examplary TOML configuration, which will be parsed into this modules types.
//!
//! ```
//! # use dfw::nftables::Nftables;
//! # use dfw::types::*;
//! # use toml;
//! # toml::from_str::<DFW<Nftables>>(r#"
//! [global_defaults]
//! external_network_interfaces = "eth0"
//!
//! [backend_defaults]
//! custom_tables = { name = "filter", chains = ["input", "forward"]}
//!
//! [backend_defaults.initialization]
//! rules = [
//!     "add table inet custom",
//! ]
//!
//! [container_to_container]
//! default_policy = "drop"
//!
//! [[container_to_container.rules]]
//! network = "common_network"
//! src_container = "container_a"
//! dst_container = "container_b"
//! verdict = "accept"
//!
//! [container_to_wider_world]
//! default_policy = "accept"
//!
//! [[container_to_container.rules]]
//! network = "other_network"
//! src_container = "container_c"
//! verdict = "drop"
//!
//! [wider_world_to_container]
//!
//! [[wider_world_to_container.rules]]
//! network = "common_network"
//! dst_container = "container_a"
//! expose_port = [80, 443]
//!
//! [container_dnat]
//!
//! [[container_dnat.rules]]
//! src_network = "common_network"
//! src_container = "container_a"
//! dst_network = "other_network"
//! dst_container = "container_c"
//! expose_port = { host_port = 8080, container_port = 80, family = "tcp" }
//! # "#).unwrap();
//! ```

use crate::{de::*, nftables, FirewallBackend, Process};
use derive_builder::Builder;
use serde::Deserialize;
use std::str::FromStr;
use strum::{Display, EnumString};

const DEFAULT_PROTOCOL: &str = "tcp";

/// `DFW` is the parent type defining the complete configuration used by DFW to build up the
/// firewall rules.
///
/// Every section is optional.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DFW<B>
where
    B: FirewallBackend,
    DFW<B>: Process<B>,
{
    /// The `defaults` configuration section.
    ///
    /// You can leave this section unspecified.
    #[serde(default, alias = "defaults")]
    pub global_defaults: GlobalDefaults,
    /// The `backend_defaults` configuration section
    #[serde(default)]
    pub backend_defaults: Option<B::Defaults>,
    /// # This field is **DEPRECATED!**
    ///
    /// Provide the custom tables in the nftables backend-defaults section instead. (This field will
    /// be removed with release 2.0.0.)
    ///
    /// Please consult the [firewall-backend documentation] if you want to know how to use this
    /// field.
    ///
    /// [firewall-backend documentation]: ../nftables/types/struct.Defaults.html#structfield.initialization
    #[deprecated(
        since = "1.2.0",
        note = "Provide the initialization in the nftables backend-defaults section instead. This \
                field will be removed with release 2.0.0."
    )]
    pub initialization: Option<nftables::types::Initialization>,
    /// The `container_to_container` configuration section
    pub container_to_container: Option<ContainerToContainer>,
    /// The `container_to_wider_world` configuration section
    pub container_to_wider_world: Option<ContainerToWiderWorld>,
    /// The `container_to_host` configuration section
    pub container_to_host: Option<ContainerToHost>,
    /// The `wider_world_to_container` configuration section
    pub wider_world_to_container: Option<WiderWorldToContainer>,
    /// The `container_dnat` configuration section
    pub container_dnat: Option<ContainerDNAT>,
}

/// The default configuration section, used by DFW for rule processing.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[serde(deny_unknown_fields)]
pub struct GlobalDefaults {
    /// This defines the external network interfaces of the host to consider during building the
    /// rules. The value can be non-existent, a string, or a sequence of strings.
    ///
    /// # Example
    ///
    /// ```
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<GlobalDefaults>(r#"
    /// external_network_interfaces = "eth0"
    /// # "#).unwrap();
    /// # toml::from_str::<GlobalDefaults>(r#"
    /// external_network_interfaces = ["eth0", "eth1"]
    /// # "#).unwrap();
    /// ```
    #[serde(default, deserialize_with = "option_string_or_seq_string")]
    pub external_network_interfaces: Option<Vec<String>>,

    /// This defines whether the default Docker bridge (usually `docker0`) is allowed to access host
    /// resources.
    ///
    /// This field is optional and will be set to "accept" by default.
    ///
    /// For non-default Docker bridges this is controlled within the [container-to-host section].
    ///
    /// [container-to-host section]: struct.ContainerToHostRule.html
    #[serde(default)]
    pub default_docker_bridge_to_host_policy: ChainPolicy,

    /// # This field is **DEPRECATED!**
    ///
    /// Provide the custom tables in the nftables backend-defaults section instead.
    /// (This field will be removed with release 2.0.0.)
    ///
    /// Please consult the [firewall-backend documentation] if you want to know how to use this
    /// field.
    ///
    /// [firewall-backend documentation]: ../nftables/types/struct.Defaults.html#structfield.custom_tables
    #[deprecated(
        since = "1.2.0",
        note = "Provide the custom tables in the nftables backend-defaults section instead. This \
                field will be removed with release 2.0.0."
    )]
    #[serde(default, deserialize_with = "option_struct_or_seq_struct")]
    pub custom_tables: Option<Vec<nftables::types::Table>>,
}

/// The container-to-container section, defining how containers can communicate amongst each other.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ContainerToContainer {
    /// The `default_policy` defines the default for when there is not a specific rule.
    ///
    /// # Filtering traffic within the same bridge
    ///
    /// Depending on how your host is configured, traffic whose origin and destination interface are
    /// the same bridge is _not_ filtered by the kernel netfilter module. This means that this
    /// default policy is not honored for traffic between containers that are on the same Docker
    /// network, but only for traffic that traverses two bridges.
    ///
    /// If your kernel has the `br_netfilter` kernel-module available, you can set the sysctl
    /// `net.bridge.bridge-nf-call-iptables` to `1` to have the netfilter-module act on traffic
    /// within the same bridge, too. You can set this value temporarily like this:
    ///
    /// ```text
    /// sysctl net.bridge.bridge-nf-call-iptables=1
    /// ```
    ///
    /// To permanently set this configuration, take a look at `man sysctl.d` and `man sysctl.conf`.
    pub default_policy: ChainPolicy,
    /// An optional list of rules, see
    /// [`ContainerToContainerRule`](struct.ContainerToContainerRule.html).
    ///
    /// # Example
    ///
    /// The easiest way to define the rules is using TOMLs [arrays of tables][toml-aot]:
    ///
    /// ```
    /// # use dfw::nftables::Nftables;
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<DFW<Nftables>>(r#"
    /// [container_to_container]
    /// default_policy = "drop"
    ///
    /// [[container_to_container.rules]]
    /// ## first rule here
    /// # network = ""
    /// # verdict = "accept"
    /// [[container_to_container.rules]]
    /// ## second rule here
    /// # network = ""
    /// # verdict = "accept"
    /// # "#).unwrap();
    /// ```
    ///
    /// [toml-aot]:
    ///  https://github.com/toml-lang/toml/blob/master/versions/en/toml-v0.4.0.md#array-of-tables
    pub rules: Option<Vec<ContainerToContainerRule>>,
}

/// Definition for a rule to be used in the container-to-container section.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ContainerToContainerRule {
    /// Common network between the source container and the destination container to apply the rule
    /// to.
    pub network: String,
    /// Source container to apply the rule to.
    pub src_container: Option<String>,
    /// Destination container to apply the rule to.
    pub dst_container: Option<String>,
    /// Additional match-string, which will be added to the nftables command.
    pub matches: Option<String>,
    /// Verdict for rule (accept, drop or reject).
    #[serde(alias = "action")]
    pub verdict: RuleVerdict,
}

/// The container-to-wider-world section, defining how containers can communicate with the wider
/// world.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ContainerToWiderWorld {
    /// The `default_policy` defines the default for when there is not a specific rule.
    pub default_policy: RuleVerdict,
    /// An optional list of rules, see
    /// [`ContainerToWiderWorldRule`](struct.ContainerToWiderWorldRule.html).
    ///
    /// # Example
    ///
    /// The easiest way to define the rules is using TOMLs [arrays of tables][toml-aot]:
    ///
    /// ```
    /// # use dfw::nftables::Nftables;
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<DFW<Nftables>>(r#"
    /// [container_to_wider_world]
    /// default_policy = "drop"
    ///
    /// [[container_to_wider_world.rules]]
    /// ## first rule here
    /// # verdict = "accept"
    /// [[container_to_wider_world.rules]]
    /// ## second rule here
    /// # verdict = "accept"
    /// # "#).unwrap();
    /// ```
    ///
    /// [toml-aot]:
    ///  https://github.com/toml-lang/toml/blob/master/versions/en/toml-v0.4.0.md#array-of-tables
    pub rules: Option<Vec<ContainerToWiderWorldRule>>,
}

/// Definition for a rule to be used in the container-to-wider-world section.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ContainerToWiderWorldRule {
    /// Network of the source container to apply the rule to.
    pub network: Option<String>,
    /// Source container to apply the rule to.
    pub src_container: Option<String>,
    /// Additional match-string, which will be added to the nftables command.
    pub matches: Option<String>,
    /// Verdict for rule (accept, drop or reject).
    #[serde(alias = "action")]
    pub verdict: RuleVerdict,
    /// Specific external network interface to target.
    pub external_network_interface: Option<String>,
}

/// The container-to-host section, defining how containers can communicate with the host.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ContainerToHost {
    /// The `default_policy` defines the default for when there is not a specific rule.
    pub default_policy: RuleVerdict,
    /// An optional list of rules, see
    /// [`ContainerToHostRule`](struct.ContainerToHostRule.html).
    ///
    /// # Example
    ///
    /// The easiest way to define the rules is using TOMLs [arrays of tables][toml-aot]:
    ///
    /// ```
    /// # use dfw::nftables::Nftables;
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<DFW<Nftables>>(r#"
    /// [container_to_host]
    /// default_policy = "drop"
    ///
    /// [[container_to_host.rules]]
    /// ## first rule here
    /// # network = ""
    /// # verdict = "accept"
    /// [[container_to_host.rules]]
    /// ## second rule here
    /// # network = ""
    /// # verdict = "accept"
    /// # "#).unwrap();
    /// ```
    ///
    /// [toml-aot]:
    ///  https://github.com/toml-lang/toml/blob/master/versions/en/toml-v0.4.0.md#array-of-tables
    pub rules: Option<Vec<ContainerToHostRule>>,
}

/// Definition for a rule to be used in the container-to-host section.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ContainerToHostRule {
    /// Network of the source container to apply the rule to.
    pub network: String,
    /// Source container to apply the rule to.
    pub src_container: Option<String>,
    /// Additional match-string, which will be added to the nftables command.
    pub matches: Option<String>,
    /// Verdict for rule (accept, drop or reject).
    #[serde(alias = "action")]
    pub verdict: RuleVerdict,
}

/// The wider-world-to-container section, defining how containers can reached from the wider world.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct WiderWorldToContainer {
    /// An optional list of rules, see
    /// [`WiderWorldToContainerRule`](struct.WiderWorldToContainerRule.html).
    ///
    /// # Example
    ///
    /// The easiest way to define the rules is using TOMLs [arrays of tables][toml-aot]:
    ///
    /// ```
    /// # use dfw::nftables::Nftables;
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<DFW<Nftables>>(r#"
    /// [[wider_world_to_container.rules]]
    /// ## first rule here
    /// # network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// [[wider_world_to_container.rules]]
    /// ## second rule here
    /// # network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// # "#).unwrap();
    /// ```
    ///
    /// [toml-aot]:
    ///  https://github.com/toml-lang/toml/blob/master/versions/en/toml-v0.4.0.md#array-of-tables
    pub rules: Option<Vec<WiderWorldToContainerRule>>,
}

/// Definition for a rule to be used in the wider-world-to-container section.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct WiderWorldToContainerRule {
    /// Network of the destination container to apply the rule to.
    pub network: String,

    /// Destination container to apply the rule to.
    pub dst_container: String,

    /// Ports to apply the rule to.
    ///
    /// Defined as:
    ///
    /// * a single integer
    ///
    /// * a single string
    ///
    /// * a single struct
    ///
    /// * a list of integers
    ///
    /// * a list of strings
    ///
    /// * a list of structs
    ///
    /// # Example
    ///
    /// All of the following are legal TOML fragments:
    ///
    /// ```
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = 80
    /// # "#).unwrap();
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = [80, 443]
    /// # "#).unwrap();
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = "53/udp"
    /// # "#).unwrap();
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = ["80/tcp", "53/udp"]
    /// # "#).unwrap();
    ///
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// ## The following four all result in the same definition
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = { host_port = 8080 }
    /// # "#).unwrap();
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = { host_port = 8080, container_port = 8080 }
    /// # "#).unwrap();
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = { host_port = 8080, family = "tcp" }
    /// # "#).unwrap();
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = { host_port = 8080, container_port = 8080, family = "tcp" }
    /// # "#).unwrap();
    ///
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// expose_port = [
    ///     { host_port = 80 },
    ///     { host_port = 53, family = "udp" },
    ///     { host_port = 443, container_port = 8443 },
    /// ]
    /// # "#).unwrap();
    /// ```
    #[serde(deserialize_with = "single_or_seq_string_or_struct")]
    pub expose_port: Vec<ExposePort>,

    /// Specific external network interface to target.
    pub external_network_interface: Option<String>,

    /// Configure if the container should be exposed via IPv6, too. _(Default: true)_.
    ///
    /// # Example
    ///
    /// ```
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// expose_via_ipv6 = false
    /// # "#).unwrap();
    ///
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// expose_via_ipv6 = false
    /// # "#).unwrap();
    /// ```
    #[serde(default = "default_wwtcr_expose_via_ipv6")]
    pub expose_via_ipv6: bool,

    /// Source CIDRs (IPv4) to which incoming traffic should be restricted.
    ///
    /// This can be:
    ///
    /// * a single string
    ///
    /// * a list of strings
    ///
    /// There is no validation whether the provided CIDRs are actually valid.
    ///
    /// # Example
    ///
    /// All of the following are legal TOML fragments:
    ///
    /// ```
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// source_cidr_v4 = "127.0.0.0/8"
    /// # "#).unwrap();
    ///
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// source_cidr_v4 = ["127.0.0.0/8", "192.0.2.1/32"]
    /// # "#).unwrap();
    /// ```
    #[serde(
        default,
        deserialize_with = "option_string_or_seq_string",
        alias = "source_cidr"
    )]
    pub source_cidr_v4: Option<Vec<String>>,

    /// Source CIDRs (IPv6) to which incoming traffic should be restricted.
    ///
    /// This can be:
    ///
    /// * a single string
    ///
    /// * a list of strings
    ///
    /// There is no validation whether the provided CIDRs are actually valid.
    ///
    /// # Example
    ///
    /// All of the following are legal TOML fragments:
    ///
    /// ```
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// source_cidr_v6 = "fe80::/10"
    /// # "#).unwrap();
    ///
    /// # toml::from_str::<WiderWorldToContainerRule>(r#"
    /// # network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// source_cidr_v6 = ["fe80::/10", "2001:db8::/32"]
    /// # "#).unwrap();
    /// ```
    #[serde(default, deserialize_with = "option_string_or_seq_string")]
    pub source_cidr_v6: Option<Vec<String>>,
}

fn default_wwtcr_expose_via_ipv6() -> bool {
    true
}

/// Struct to hold a port definition to expose on the host/between containers.
#[derive(Deserialize, Debug, Clone, Default, Builder, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ExposePort {
    /// Port the `container_port` should be exposed to on the host.
    #[builder(field(public))]
    pub host_port: u16,

    /// Port the `host_port` should map to into the container.
    #[builder(field(public), default = "self.default_container_port()")]
    pub container_port: Option<u16>,

    /// Family of the exposed port.
    ///
    /// Can be left blank, `tcp` will be used as default.
    #[serde(default = "default_expose_port_family")]
    #[builder(field(public), default = "self.default_family()")]
    pub family: String,
}

impl ExposePortBuilder {
    fn client_and_host_port(&mut self, value: &str) -> Result<&mut Self, String> {
        let split: Vec<&str> = value.split(':').collect();
        match split.len() {
            1 => self.host_port = Some(split[0].parse().map_err(|e| format!("{}", e))?),
            2 => {
                self.host_port = Some(split[0].parse().map_err(|e| format!("{}", e))?);
                self.container_port = Some(Some(split[1].parse().map_err(|e| format!("{}", e))?));
            }
            _ => return Err(format!("port string has invalid format '{}'", value)),
        }
        Ok(self)
    }

    fn default_container_port(&self) -> Option<u16> {
        None
    }

    fn default_family(&self) -> String {
        DEFAULT_PROTOCOL.to_owned()
    }
}

impl FromStr for ExposePort {
    type Err = String;

    /// Convert a formatted string into a [`ExposePort`](struct.ExposePort.html).
    ///
    /// The string has to be in the format `<HOST_PORT>[:<CONTAINER_PORT>]/<FAMILY>`, i.e.
    /// `80:8080/tcp`. If you don't specify the container-port, it is assumed to be identical to the
    /// host-port.
    ///
    /// # Example
    ///
    /// ```
    /// # use dfw::types::ExposePort;
    /// let port: ExposePort = "80".parse().unwrap();
    /// assert_eq!(port.host_port, 80);
    /// assert_eq!(port.container_port, None);
    /// assert_eq!(port.family, "tcp");
    /// ```
    ///
    /// ```
    /// # use dfw::types::ExposePort;
    /// let port: ExposePort = "53/udp".parse().unwrap();
    /// assert_eq!(port.host_port, 53);
    /// assert_eq!(port.container_port, None);
    /// assert_eq!(port.family, "udp");
    /// ```
    ///
    /// ```
    /// # use dfw::types::ExposePort;
    /// let port: ExposePort = "80:8080/tcp".parse().unwrap();
    /// assert_eq!(port.host_port, 80);
    /// assert_eq!(port.container_port, Some(8080));
    /// assert_eq!(port.family, "tcp");
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split: Vec<&str> = s.split('/').collect();
        Ok(match split.len() {
            1 => ExposePortBuilder::default()
                .client_and_host_port(split[0])?
                .build()
                .map_err(|error| format!("{}", error))?,
            2 => ExposePortBuilder::default()
                .client_and_host_port(split[0])?
                .family(split[1].to_owned())
                .build()
                .map_err(|error| format!("{}", error))?,
            _ => return Err(format!("port string has invalid format '{}'", s)),
        })
    }
}

/// The container-DNAT section, defining how containers can communicate with each other over
/// non-common networks.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ContainerDNAT {
    /// An optional list of rules, see
    /// [`ContainerDNATRule`](struct.ContainerDNATRule.html).
    ///
    /// # Example
    ///
    /// The easiest way to define the rules is using TOMLs [arrays of tables][toml-aot]:
    ///
    /// ```
    /// # use dfw::nftables::Nftables;
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<DFW<Nftables>>(r#"
    /// [[container_dnat.rules]]
    /// ## first rule here
    /// # dst_network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// [[container_dnat.rules]]
    /// ## second rule here
    /// # dst_network = ""
    /// # dst_container = ""
    /// # expose_port = 0
    /// # "#).unwrap();
    /// ```
    ///
    /// [toml-aot]:
    ///  https://github.com/toml-lang/toml/blob/master/versions/en/toml-v0.4.0.md#array-of-tables
    pub rules: Option<Vec<ContainerDNATRule>>,
}

/// Definition for a rule to be used in the container-DNAT section.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ContainerDNATRule {
    /// Network of the source container to apply the rule to.
    pub src_network: Option<String>,

    /// Source container to apply the rule to.
    pub src_container: Option<String>,

    /// Network of the destination container to apply the rule to.
    pub dst_network: String,

    /// Destination container to apply the rule to.
    pub dst_container: String,

    /// Ports to apply the rule to.
    ///
    /// Defined as:
    ///
    /// * a single integer
    ///
    /// * a single string
    ///
    /// * a single struct
    ///
    /// * a list of integers
    ///
    /// * a list of strings
    ///
    /// * a list of structs
    ///
    /// # Example
    ///
    /// All of the following are legal TOML fragments:
    ///
    /// ```
    /// # use dfw::types::*;
    /// # use toml;
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = 80
    /// # "#).unwrap();
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = [80, 443]
    /// # "#).unwrap();
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = "53/udp"
    /// # "#).unwrap();
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = ["80/tcp", "53/udp"]
    /// # "#).unwrap();
    ///
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// ## The following four all result in the same definition
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = { host_port = 8080 }
    /// # "#).unwrap();
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = { host_port = 8080, container_port = 8080 }
    /// # "#).unwrap();
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = { host_port = 8080, family = "tcp" }
    /// # "#).unwrap();
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = { host_port = 8080, container_port = 8080, family = "tcp" }
    /// # "#).unwrap();
    ///
    /// # toml::from_str::<ContainerDNATRule>(r#"
    /// # dst_network = ""
    /// # dst_container = ""
    /// expose_port = [
    ///     { host_port = 80 },
    ///     { host_port = 53, family = "udp" },
    ///     { host_port = 443, container_port = 8443 },
    /// ]
    /// # "#).unwrap();
    /// ```
    #[serde(deserialize_with = "single_or_seq_string_or_struct")]
    pub expose_port: Vec<ExposePort>,
}

fn default_expose_port_family() -> String {
    DEFAULT_PROTOCOL.to_owned()
}

/// Representation of chain policies.
///
/// ## Attribution
///
/// Parts of the documentation have been taken from
/// <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains>.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "snake_case")]
pub enum ChainPolicy {
    /// The accept verdict means that the packet will keep traversing the network stack.
    #[strum(to_string = "accept", serialize = "ACCEPT")]
    #[serde(alias = "ACCEPT")]
    #[default]
    Accept,
    /// The drop verdict means that the packet is discarded if the packet reaches the end of the
    /// base chain.
    #[strum(to_string = "drop", serialize = "DROP")]
    #[serde(alias = "DROP")]
    Drop,
}

impl slog::Value for ChainPolicy {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        self.to_string().serialize(record, key, serializer)
    }
}

/// Representation of rule policies.
///
/// ## Attribution
///
/// Parts of the documentation have been taken from
/// <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains>.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Display, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "snake_case")]
pub enum RuleVerdict {
    /// The accept verdict means that the packet will keep traversing the network stack.
    #[serde(alias = "ACCEPT")]
    #[strum(to_string = "accept", serialize = "ACCEPT")]
    #[default]
    Accept,
    /// The drop verdict means that the packet is discarded if the packet reaches the end of the
    /// base chain.
    #[serde(alias = "DROP")]
    #[strum(to_string = "drop", serialize = "DROP")]
    Drop,
    /// The reject verdict means that the packet is responded to with an ICMP message stating that
    /// it was rejected.
    #[serde(alias = "REJECT")]
    #[strum(to_string = "reject", serialize = "REJECT")]
    Reject,
}

impl slog::Value for RuleVerdict {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        self.to_string().serialize(record, key, serializer)
    }
}
#[cfg(test)]
mod test {
    use super::{ChainPolicy, RuleVerdict};
    use std::str::FromStr;

    #[test]
    fn chainpolicy_fromstr() {
        assert_eq!(ChainPolicy::Accept, FromStr::from_str("accept").unwrap());
        assert_eq!(ChainPolicy::Accept, FromStr::from_str("ACCEPT").unwrap());
        assert_eq!(ChainPolicy::Drop, FromStr::from_str("drop").unwrap());
        assert_eq!(ChainPolicy::Drop, FromStr::from_str("DROP").unwrap());
    }

    #[test]
    fn chainpolicy_tostring() {
        assert_eq!("accept", &ChainPolicy::Accept.to_string());
        assert_eq!("drop", &ChainPolicy::Drop.to_string());
    }

    #[test]
    fn ruleverdict_fromstr() {
        assert_eq!(RuleVerdict::Accept, FromStr::from_str("accept").unwrap());
        assert_eq!(RuleVerdict::Accept, FromStr::from_str("ACCEPT").unwrap());
        assert_eq!(RuleVerdict::Drop, FromStr::from_str("drop").unwrap());
        assert_eq!(RuleVerdict::Drop, FromStr::from_str("DROP").unwrap());
        assert_eq!(RuleVerdict::Reject, FromStr::from_str("reject").unwrap());
        assert_eq!(RuleVerdict::Reject, FromStr::from_str("REJECT").unwrap());
    }

    #[test]
    fn ruleverdict_tostring() {
        assert_eq!("accept", &RuleVerdict::Accept.to_string());
        assert_eq!("drop", &RuleVerdict::Drop.to_string());
        assert_eq!("reject", &RuleVerdict::Reject.to_string());
    }
}
