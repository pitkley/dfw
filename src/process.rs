// Copyright 2017 - 2019 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! This module holds the types related to configuration processing and rule creation.

use crate::errors::*;
use crate::nftables::{self, Family, Hook, RuleVerdict, Type};
use crate::rule::*;
use crate::types::*;
use crate::util::FutureExt;
use failure::{bail, format_err, ResultExt};
use shiplift::builder::{ContainerFilter as ContainerFilterShiplift, ContainerListOptions};
use shiplift::rep::Container;
use shiplift::rep::{NetworkContainerDetails, NetworkDetails};
use shiplift::Docker;
use slog::Logger;
use slog::{debug, info, o, trace};
use std::collections::HashMap as Map;
use std::io::prelude::*;
use std::io::BufWriter;
use std::process::Command;
use tempfile;
use time;

const NF_IP_PRI_NAT_DST: i16 = -100;
const NF_IP_PRI_FILTER: i16 = 0;
const NF_IP_PRI_NAT_SRC: i16 = 100;

const NF_PRIORITY_IP_NAT_PREROUTING_DFW: i16 = NF_IP_PRI_NAT_DST - 5;
const NF_PRIORITY_IP6_NAT_PREROUTING_DFW: i16 = NF_IP_PRI_NAT_DST - 5;
const NF_PRIORITY_INET_FILTER_ANY_DFW: i16 = NF_IP_PRI_FILTER - 5;
const NF_PRIORITY_IP_NAT_POSTROUTING_DFW: i16 = NF_IP_PRI_NAT_SRC - 5;
const NF_PRIORITY_IP6_NAT_POSTROUTING_DFW: i16 = NF_IP_PRI_NAT_SRC - 5;

pub(crate) const DFW_MARK: &str = "0xdf";

/// This trait allows a type to define its own processing rules. It is expected to return a list
/// of rules that can be applied with nft.
///
/// # Example
///
/// ```
/// # use dfw::process::{Process, ProcessContext};
/// # use failure::Error;
/// struct MyType {
///     rules: Vec<String>,
/// }
///
/// impl Process for MyType {
///     fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>, Error> {
///         let mut rules = Vec::new();
///         for rule in &self.rules {
///             rules.push(format!("add rule {}", rule));
///         }
///         Ok(Some(rules))
///     }
/// }
/// ```
pub trait Process {
    /// Process the current type within the given [`ProcessContext`], returning zero or more rules
    /// to apply with nft.
    ///
    /// [`ProcessContext`]: struct.ProcessContext.html
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>>;
}

impl<T> Process for Option<T>
where
    T: Process,
{
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        match self {
            Some(t) => t.process(ctx),
            None => Ok(None),
        }
    }
}

impl<T> Process for Vec<T>
where
    T: Process,
{
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();
        for rule in self {
            if let Some(mut sub_rules) = rule.process(ctx)? {
                rules.append(&mut sub_rules);
            }
        }

        Ok(Some(rules))
    }
}

impl Process for DFW {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        info!(ctx.logger, "Starting processing";
              o!("started_processing_at" => time::OffsetDateTime::now().format("%FT%T%z")));
        let mut rules = vec![
            nftables::add_table(Family::Inet, "dfw"),
            nftables::flush_table(Family::Inet, "dfw"),
            nftables::add_base_chain(
                Family::Inet,
                "dfw",
                "input",
                Type::Filter,
                Hook::Input,
                NF_PRIORITY_INET_FILTER_ANY_DFW,
            ),
            nftables::add_rule(Family::Inet, "dfw", "input", "ct state invalid drop"),
            nftables::add_rule(
                Family::Inet,
                "dfw",
                "input",
                "ct state { related, established } accept",
            ),
            nftables::add_base_chain(
                Family::Inet,
                "dfw",
                "forward",
                Type::Filter,
                Hook::Forward,
                NF_PRIORITY_INET_FILTER_ANY_DFW,
            ),
            nftables::add_rule(Family::Inet, "dfw", "forward", "ct state invalid drop"),
            nftables::add_rule(
                Family::Inet,
                "dfw",
                "forward",
                "ct state { related, established } accept",
            ),
            nftables::add_table(Family::Ip, "dfw"),
            nftables::flush_table(Family::Ip, "dfw"),
            nftables::add_base_chain(
                Family::Ip,
                "dfw",
                "prerouting",
                Type::Nat,
                Hook::Prerouting,
                NF_PRIORITY_IP_NAT_PREROUTING_DFW,
            ),
            nftables::add_base_chain(
                Family::Ip,
                "dfw",
                "postrouting",
                Type::Nat,
                Hook::Postrouting,
                NF_PRIORITY_IP_NAT_POSTROUTING_DFW,
            ),
            nftables::add_table(Family::Ip6, "dfw"),
            nftables::flush_table(Family::Ip6, "dfw"),
            nftables::add_base_chain(
                Family::Ip6,
                "dfw",
                "prerouting",
                Type::Nat,
                Hook::Prerouting,
                NF_PRIORITY_IP6_NAT_PREROUTING_DFW,
            ),
            nftables::add_base_chain(
                Family::Ip6,
                "dfw",
                "postrouting",
                Type::Nat,
                Hook::Postrouting,
                NF_PRIORITY_IP6_NAT_POSTROUTING_DFW,
            ),
        ];
        for sub_rules in vec![
            self.initialization.process(ctx)?,
            self.defaults.process(ctx)?,
            self.container_to_container.process(ctx)?,
            self.container_to_wider_world.process(ctx)?,
            self.container_to_host.process(ctx)?,
            self.wider_world_to_container.process(ctx)?,
            self.container_dnat.process(ctx)?,
        ] {
            if let Some(mut sub_rules) = sub_rules {
                rules.append(&mut sub_rules);
            }
        }

        info!(ctx.logger, "Finished processing";
             o!("finished_processing_at" => time::OffsetDateTime::now().format("%FT%T%z")));

        Ok(Some(rules))
    }
}

impl Process for Initialization {
    fn process(&self, _ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        Ok(self.rules.clone())
    }
}

impl Process for Defaults {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();

        // Hook into other chains if requested
        if let Some(ref custom_tables) = self.custom_tables {
            for custom_table in custom_tables {
                for chain in &custom_table.chains {
                    let mut additional_rules = Vec::new();

                    // This is a small helper macro to de-duplicate the "add if it doesn't already
                    // exist" logic. It essentially generates a marker which uniquely identifies a
                    // rule, checks if that marker is already in the current ruleset, and if not,
                    // adds it. This enables us to not duplicate rules that are outside of our table
                    // where flushing is not an option.
                    macro_rules! m {
                        ($mark:expr, $rule:expr) => {
                            let marker =
                                generate_marker(&["defaults", &custom_table.name, chain, $mark]);
                            if !ctx.marker_in_current_ruleset(&marker) {
                                additional_rules.push(nftables::insert_rule(
                                    Family::Inet,
                                    &custom_table.name,
                                    chain,
                                    &format!("{} comment \"{}\"", $rule, marker),
                                    None,
                                ));
                            }
                        };
                    }
                    // Handle `ct state invalid drop` rule
                    m!("ct-state-invalid-drop", "ct state invalid drop");
                    // Handle `ct state { related, established } accept` rule
                    m!(
                        "ct-state-relatedestablished-accept",
                        "ct state { related, established } accept"
                    );
                    // Handle `meta mark ... accept` rule
                    m!(
                        "meta-mark",
                        &format!("meta mark and {} == {} accept", DFW_MARK, DFW_MARK)
                    );

                    // The rules above are not added at the end, but inserted at the top. We thus
                    // reverse the order of the rules here to effectively retain the initial order
                    // of the vec.
                    additional_rules.reverse();
                    rules.append(&mut additional_rules);
                }
            }
        }

        // Enforce policy for default Docker-bridge (usually docker0) to access host-resources
        if let Some(bridge_network) = ctx.network_map.get("bridge") {
            if let Some(bridge_name) = bridge_network
                .options
                .as_ref()
                .ok_or_else(|| format_err!("couldn't get network options"))?
                .get("com.docker.network.bridge.name")
            {
                // Set policy for input-chain
                rules.push(nftables::add_rule(
                    Family::Inet,
                    "dfw",
                    "input",
                    &format!(
                        "meta iifname {} meta mark set {} {}",
                        bridge_name, DFW_MARK, self.default_docker_bridge_to_host_policy,
                    ),
                ));

                // Set policy for forward-chain, divided by the external network interfaces.
                if let Some(ref external_network_interfaces) = self.external_network_interfaces {
                    for external_network_interface in external_network_interfaces {
                        rules.push(nftables::add_rule(
                            Family::Inet,
                            "dfw",
                            "forward",
                            &format!(
                                "meta iifname {} oifname {} meta mark set {} {}",
                                bridge_name,
                                external_network_interface,
                                DFW_MARK,
                                self.default_docker_bridge_to_host_policy,
                            ),
                        ))
                    }
                }
            }
        }

        // Configure postrouting
        if let Some(ref external_network_interfaces) = self.external_network_interfaces {
            for external_network_interface in external_network_interfaces {
                // Configure postrouting
                rules.push(nftables::add_rule(
                    Family::Ip,
                    "dfw",
                    "postrouting",
                    &format!(
                        "meta oifname {} meta mark set {} masquerade",
                        external_network_interface, DFW_MARK,
                    ),
                ));
                rules.push(nftables::add_rule(
                    Family::Ip6,
                    "dfw",
                    "postrouting",
                    &format!(
                        "meta oifname {} meta mark set {} masquerade",
                        external_network_interface, DFW_MARK,
                    ),
                ));
            }
        }
        Ok(Some(rules))
    }
}

impl Process for ContainerToContainer {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();

        // Enforce default policy for container-to-container communication.
        rules.push(nftables::set_chain_policy(
            Family::Inet,
            "dfw",
            "forward",
            self.default_policy,
        ));

        if let Some(mut ctc_rules) = self.rules.process(ctx)? {
            rules.append(&mut ctc_rules);
        }

        Ok(Some(rules))
    }
}

impl Process for ContainerToContainerRule {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();
        let mut nft_rule = RuleBuilder::default();
        let network = match ctx.network_map.get(&self.network) {
            Some(network) => network,
            None => return Ok(None),
        };
        trace!(ctx.logger, "Got network";
                    o!("network_name" => &self.network,
                        "network" => format!("{:?}", network)));
        let bridge_name = get_bridge_name(&network.id)?;
        trace!(ctx.logger, "Got bridge name";
                    o!("network_name" => &network.name,
                        "bridge_name" => &bridge_name));

        nft_rule
            .in_interface(&bridge_name)
            .out_interface(&bridge_name);

        if let Some(ref src_container) = self.src_container {
            trace!(ctx.logger, "Getting network for container");
            let src_network = match get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                src_container,
                &network.id,
            )? {
                Some(src_network) => src_network,
                None => return Ok(None),
            };
            trace!(ctx.logger, "Got source network";
                        o!("network_name" => &network.name,
                            "src_network" => format!("{:?}", src_network)));

            let bridge_name = get_bridge_name(&network.id)?;
            trace!(ctx.logger, "Got bridge name";
                        o!("network_name" => &network.name,
                            "bridge_name" => &bridge_name));

            nft_rule
                .in_interface(&bridge_name)
                .out_interface(&bridge_name)
                .source_address(
                    src_network
                        .ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                );
        }

        if let Some(ref dst_container) = self.dst_container {
            let dst_network = match get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                dst_container,
                &network.id,
            )? {
                Some(dst_network) => dst_network,
                None => return Ok(None),
            };
            trace!(ctx.logger, "Got destination network";
                        o!("network_name" => &network.name,
                            "dst_network" => format!("{:?}", dst_network)));

            let bridge_name = get_bridge_name(&network.id)?;
            trace!(ctx.logger, "Got bridge name";
                        o!("network_name" => &network.name,
                            "bridge_name" => &bridge_name));

            nft_rule.out_interface(&bridge_name).destination_address(
                dst_network
                    .ipv4_address
                    .split('/')
                    .next()
                    .ok_or_else(|| format_err!("IPv4 address is empty"))?,
            );
        }

        if let Some(matches) = &self.matches {
            nft_rule.matches(matches);
        }
        nft_rule.verdict(self.verdict);

        let rule = nft_rule.build()?;
        rules.push(nftables::add_rule(Family::Inet, "dfw", "forward", &rule));

        Ok(Some(rules))
    }
}

impl Process for ContainerToWiderWorld {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();

        if let Some(mut ctww_rules) = self.rules.process(ctx)? {
            rules.append(&mut ctww_rules);
        }

        // Enforce default policy for container-to-wider-world communication.
        if let Some(external_network_interfaces) = &ctx.external_network_interfaces {
            debug!(ctx.logger, "Set default policy for external network interfaces";
                   o!("part" => "container_to_wider_world",
                      "external_network_interfaces" => format!("{:?}", external_network_interfaces),
                      "default_policy" => &self.default_policy));
            for external_network_interface in external_network_interfaces {
                trace!(ctx.logger, "Process default policy for external network interface";
                       o!("part" => "container_to_wider_world",
                          "external_network_interface" => external_network_interface,
                          "default_policy" => &self.default_policy));
                for network in ctx.network_map.values() {
                    let bridge_name = get_bridge_name(&network.id)?;
                    trace!(ctx.logger, "Got bridge name";
                           o!("network_name" => &network.name,
                              "bridge_name" => &bridge_name));

                    let rule = RuleBuilder::default()
                        .in_interface(&bridge_name)
                        .out_interface(external_network_interface)
                        .verdict(self.default_policy)
                        .build()?;

                    debug!(ctx.logger, "Add forward rule for default policy";
                           o!("part" => "container_to_wider_world",
                              "external_network_interface" => external_network_interface,
                              "default_policy" => &self.default_policy,
                              "rule" => &rule));

                    rules.push(nftables::add_rule(Family::Inet, "dfw", "forward", &rule));
                }
            }
        }

        Ok(Some(rules))
    }
}

impl Process for ContainerToWiderWorldRule {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();
        debug!(ctx.logger, "Process rule";
                   o!("part" => "container_to_wider_world",
                      "rule" => format!("{:?}", self)));
        let mut nft_rule = RuleBuilder::default();

        if let Some(ref network) = self.network {
            if let Some(network) = ctx.network_map.get(network) {
                let bridge_name = get_bridge_name(&network.id)?;
                trace!(ctx.logger, "Got bridge name";
                           o!("network_name" => &network.name,
                              "bridge_name" => &bridge_name));

                nft_rule.in_interface(&bridge_name);

                if let Some(ref src_container) = self.src_container {
                    if let Some(src_network) = get_network_for_container(
                        ctx.docker,
                        &ctx.container_map,
                        src_container,
                        &network.id,
                    )? {
                        trace!(ctx.logger, "Got source network";
                                   o!("network_name" => &network.name,
                                      "src_network" => format!("{:?}", src_network)));

                        let bridge_name = get_bridge_name(&network.id)?;
                        trace!(ctx.logger, "Got bridge name";
                                   o!("network_name" => &network.name,
                                      "bridge_name" => &bridge_name));

                        nft_rule.in_interface(&bridge_name).source_address(
                            src_network
                                .ipv4_address
                                .split('/')
                                .next()
                                .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                        );
                    }
                } else {
                    let bridge_name = get_bridge_name(&network.id)?;
                    trace!(ctx.logger, "Got bridge name";
                               o!("network_name" => &network.name,
                                  "bridge_name" => &bridge_name));

                    nft_rule.in_interface(&bridge_name);
                }
            }
        }

        if let Some(ref matches) = self.matches {
            nft_rule.matches(matches);
        }

        nft_rule.verdict(self.verdict);

        // Try to build the rule without the out_interface defined to see if any of the other
        // mandatory fields has been populated.
        debug!(ctx.logger, "Build rule to verify contents";
                   o!("args" => format!("{:?}", nft_rule)));
        // TODO: maybe add a `verify` method to `Rule`
        nft_rule.build().context(format!(
            "failed to build rule, maybe the network `{:?}` or container `{:?}` doesn't exist",
            self.network, self.src_container
        ))?;

        if let Some(ref external_network_interface) = self.external_network_interface {
            trace!(ctx.logger, "Rule has specific external network interface";
                       o!("external_network_interface" => external_network_interface));
            nft_rule.out_interface(external_network_interface);
        } else if let Some(ref primary_external_network_interface) =
            ctx.primary_external_network_interface
        {
            trace!(ctx.logger, "Rule uses primary external network interface";
                       o!("external_network_interface" => primary_external_network_interface));
            nft_rule.out_interface(primary_external_network_interface);
        }

        let rule = nft_rule.build()?;
        debug!(ctx.logger, "Add forward rule";
                   o!("part" => "container_to_wider_world",
                      "rule" => &rule));

        // Apply the rule
        rules.push(nftables::add_rule(Family::Inet, "dfw", "forward", &rule));
        Ok(Some(rules))
    }
}

impl Process for ContainerToHost {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();

        if let Some(mut cth_rules) = self.rules.process(ctx)? {
            rules.append(&mut cth_rules);
        }

        // Default policy
        for network in ctx.network_map.values() {
            let bridge_name = get_bridge_name(&network.id)?;
            trace!(ctx.logger, "Got bridge name";
                   o!("network_name" => &network.name,
                      "bridge_name" => &bridge_name));

            let rule = RuleBuilder::default()
                .in_interface(&bridge_name)
                .verdict(self.default_policy)
                .build()?;

            trace!(ctx.logger, "Add input rule for default policy";
                   o!("part" => "container_to_host",
                      "default_policy" => self.default_policy,
                      "rule" => &rule));
            rules.push(nftables::add_rule(Family::Inet, "dfw", "input", &rule));
        }

        Ok(Some(rules))
    }
}

impl Process for ContainerToHostRule {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();
        debug!(ctx.logger, "Process rule";
                   o!("part" => "container_to_host",
                      "rule" => format!("{:?}", self)));
        let mut nft_rule = RuleBuilder::default();

        let network = match ctx.network_map.get(&self.network) {
            Some(network) => network,
            None => return Ok(None),
        };
        trace!(ctx.logger, "Got network";
                   o!("network_name" => &network.name,
                      "network" => format!("{:?}", network)));

        let bridge_name = get_bridge_name(&network.id)?;
        trace!(ctx.logger, "Got bridge name";
                   o!("network_name" => &network.name,
                      "bridge_name" => &bridge_name));

        nft_rule.in_interface(&bridge_name);

        if let Some(ref src_container) = self.src_container {
            if let Some(src_network) = get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                src_container,
                &network.id,
            )? {
                trace!(ctx.logger, "Got source network";
                           o!("network_name" => &network.name,
                              "src_network" => format!("{:?}", src_network)));
                nft_rule.source_address(
                    src_network
                        .ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                );
            }
        }

        if let Some(ref matches) = self.matches {
            nft_rule.matches(matches);
        }

        nft_rule.verdict(self.verdict);

        // Try to build the rule without the out_interface defined to see if any of the other
        // mandatory fields has been populated.
        debug!(ctx.logger, "Build rule to verify contents";
                   o!("args" => format!("{:?}", nft_rule)));
        // TODO: maybe add a `verify` method to `Rule`
        nft_rule.build().context(format!(
            "failed to build rule, maybe the container `{:?}` doesn't exist",
            self.src_container
        ))?;

        let rule = nft_rule.build()?;
        debug!(ctx.logger, "Add input rule";
                   o!("part" => "container_to_host",
                      "rule" => &rule));

        // Apply the rule
        rules.push(nftables::add_rule(Family::Inet, "dfw", "input", &rule));

        Ok(Some(rules))
    }
}

impl Process for WiderWorldToContainer {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        if self.rules.is_some() {
            debug!(ctx.logger, "Process rules";
                   o!("part" => "wider_world_to_container"));
            self.rules.process(ctx)
        } else {
            trace!(ctx.logger, "No rules";
                   o!("part" => "wider_world_to_container"));
            Ok(None)
        }
    }
}

impl Process for WiderWorldToContainerRule {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();
        debug!(ctx.logger, "Process rule";
                   o!("part" => "wider_world_to_container",
                      "rule" => format!("{:?}", self)));
        for expose_port in &self.expose_port {
            let mut nft_forward_rule = RuleBuilder::default();
            let mut nft_dnat_rule = RuleBuilder::default();
            let mut nft_mark_rule = RuleBuilder::default();

            let network = match ctx.network_map.get(&self.network) {
                Some(network) => network,
                None => return Ok(None),
            };
            trace!(ctx.logger, "Got network";
                   o!("network_name" => &network.name,
                      "network" => format!("{:?}", network)));

            let bridge_name = get_bridge_name(&network.id)?;
            trace!(ctx.logger, "Got bridge name";
                   o!("network_name" => &network.name,
                      "bridge_name" => &bridge_name));

            nft_forward_rule.out_interface(&bridge_name);

            if let Some(dst_network) = get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                &self.dst_container,
                &network.id,
            )? {
                trace!(ctx.logger, "Got destination network";
                       o!("network_name" => &network.name,
                          "dst_network" => format!("{:?}", dst_network)));

                nft_forward_rule.destination_address(
                    dst_network
                        .ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                );

                let destination_port = match expose_port.container_port {
                    Some(destination_port) => destination_port.to_string(),
                    None => expose_port.host_port.to_string(),
                };
                nft_forward_rule.destination_port(&destination_port);
                nft_dnat_rule.destination_port(&destination_port);
                nft_dnat_rule.dnat(&format!(
                    "{}:{}",
                    dst_network
                        .ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                    destination_port
                ));
                nft_mark_rule.destination_port(&destination_port);
            // TODO: correct IPv6 handling would include actually using IPv6-addresses.
            // While the code below is correct, the postrouting did not work and I was unable to
            // actually get traffic from an IPv6-enabled container back.
            // if !dst_network.ipv6_address.is_empty() {
            //     nft_mark_rule.dnat(&format!(
            //         "{}:{}",
            //         dst_network.ipv6_address
            //         .split('/')
            //         .next()
            //         .ok_or_else(|| format_err!("Invalid IPv6 address"))?,
            //     destination_port));
            // }
            } else {
                // Network for container has to exist
                return Ok(None);
            }

            // Set correct protocol
            nft_forward_rule.protocol(&expose_port.family);
            nft_dnat_rule.protocol(&expose_port.family);
            nft_mark_rule.protocol(&expose_port.family);

            nft_forward_rule.verdict(RuleVerdict::Accept);

            // Try to build the rule without the out_interface defined to see if any of the
            // other mandatory fields has been populated.
            debug!(ctx.logger, "Build rule to verify contents";
                   o!("args" => format!("{:?}", nft_forward_rule)));
            nft_forward_rule.build()?; // TODO: maybe add a `verify` method to `Rule`
            debug!(ctx.logger, "build rule to verify contents";
                   o!("args" => format!("{:?}", nft_dnat_rule)));
            nft_dnat_rule.build()?; // todo: maybe add a `verify` method to `rule`
            debug!(ctx.logger, "Build rule to verify contents";
                   o!("args" => format!("{:?}", nft_mark_rule)));
            nft_mark_rule.build()?; // TODO: maybe add a `verify` method to `Rule`

            if let Some(ref external_network_interface) = self.external_network_interface {
                trace!(ctx.logger, "Rule has specific external network interface";
                       o!("external_network_interface" => external_network_interface));

                nft_forward_rule.in_interface(external_network_interface);
                nft_dnat_rule.in_interface(external_network_interface);
                nft_mark_rule.in_interface(external_network_interface);
            } else if let Some(ref primary_external_network_interface) =
                ctx.primary_external_network_interface
            {
                trace!(ctx.logger, "Rule uses primary external network interface";
                       o!("external_network_interface" => primary_external_network_interface));

                nft_forward_rule.in_interface(primary_external_network_interface);
                nft_dnat_rule.in_interface(primary_external_network_interface);
                nft_mark_rule.in_interface(primary_external_network_interface);
            } else {
                // The DNAT rule requires the external interface
                return Ok(None);
            }

            // If source CIDRs have been specified, create the FORWARD-rules as required to
            // restrict the traffic as intended.
            if let Some(source_cidrs_v4) = &self.source_cidr_v4 {
                self.apply_source_cidrs_v4(
                    ctx,
                    &mut rules,
                    source_cidrs_v4,
                    nft_forward_rule.clone(),
                    nft_dnat_rule.clone(),
                )?;
            }
            if let Some(source_cidrs_v6) = &self.source_cidr_v6 {
                self.apply_source_cidrs_v6(
                    ctx,
                    &mut rules,
                    source_cidrs_v6,
                    nft_mark_rule.clone(),
                )?;
            }

            // If no source CIDRs were specified, we create the default rules that allow all
            // connections from any IP.
            if self.source_cidr_v4.is_none() && self.source_cidr_v6.is_none() {
                let forward_rule = nft_forward_rule.build()?;
                debug!(ctx.logger, "Add forward rule";
                       o!("part" => "wider_world_to_container",
                          "rule" => &forward_rule));
                let dnat_rule = nft_dnat_rule.build()?;
                debug!(ctx.logger, "Add DNAT rule";
                       o!("part" => "wider_world_to_container",
                          "rule" => &dnat_rule));
                let mark_rule = nft_mark_rule.build()?;
                debug!(ctx.logger, "Add mark rule";
                       o!("part" => "wider_world_to_container",
                          "rule" => &mark_rule));
                // Apply the rule
                rules.push(nftables::add_rule(
                    Family::Inet,
                    "dfw",
                    "forward",
                    &forward_rule,
                ));
                rules.push(nftables::add_rule(
                    Family::Ip,
                    "dfw",
                    "prerouting",
                    &dnat_rule,
                ));
                rules.push(nftables::add_rule(
                    Family::Ip6,
                    "dfw",
                    "prerouting",
                    &mark_rule,
                ));
            }
        }

        Ok(Some(rules))
    }
}

impl WiderWorldToContainerRule {
    fn apply_source_cidrs_v4(
        &self,
        ctx: &ProcessContext,
        rules: &mut Vec<String>,
        source_cidrs: &[String],
        nft_forward_rule: RuleBuilder,
        nft_dnat_rule: RuleBuilder,
    ) -> Result<()> {
        debug!(ctx.logger, "Generate extended FORWARD rules, source CIDRs (IPv4) were specified";
               o!("args" => format!("{:?}", nft_dnat_rule),
                  "source_cidrs" => source_cidrs.join(", ")));
        for additional_forward_rule in source_cidrs
            .iter()
            .map(|source_cidr| {
                let mut forward_rule = nft_forward_rule.clone();
                forward_rule.source_address(source_cidr);
                forward_rule
            })
            .map(|forward_rule| forward_rule.build())
            .collect::<Result<Vec<_>>>()?
        {
            debug!(ctx.logger, "Add FORWARD rule";
                   o!("part" => "wider_world_to_container",
                      "rule" => &additional_forward_rule));
            rules.push(nftables::add_rule(
                Family::Inet,
                "dfw",
                "forward",
                &additional_forward_rule,
            ));
        }
        for additional_dnat_rule in source_cidrs
            .iter()
            .map(|source_cidr| {
                let mut dnat_rule = nft_dnat_rule.clone();
                dnat_rule.source_address(source_cidr);
                dnat_rule
            })
            .map(|dnat_rule| dnat_rule.build())
            .collect::<Result<Vec<_>>>()?
        {
            debug!(ctx.logger, "Add DNAT rule";
                   o!("part" => "wider_world_to_container",
                      "rule" => &additional_dnat_rule));
            rules.push(nftables::add_rule(
                Family::Ip,
                "dfw",
                "prerouting",
                &additional_dnat_rule,
            ));
        }

        Ok(())
    }

    fn apply_source_cidrs_v6(
        &self,
        ctx: &ProcessContext,
        rules: &mut Vec<String>,
        source_cidrs: &[String],
        nft_mark_rule: RuleBuilder,
    ) -> Result<()> {
        debug!(ctx.logger, "Generate extended prerouting rules, source CIDRs (IPv6) were specified";
               o!("args" => format!("{:?}", nft_mark_rule),
                  "source_cidrs" => source_cidrs.join(", ")));
        for additional_mark_rule in source_cidrs
            .iter()
            .map(|source_cidr| {
                let mut mark_rule = nft_mark_rule.clone();
                mark_rule.source_address_v6(source_cidr);
                mark_rule
            })
            .map(|dnat_rule| dnat_rule.build())
            .collect::<Result<Vec<_>>>()?
        {
            debug!(ctx.logger, "Add mark rule";
                            o!("part" => "wider_world_to_container",
                               "rule" => &additional_mark_rule));
            rules.push(nftables::add_rule(
                Family::Ip6,
                "dfw",
                "prerouting",
                &additional_mark_rule,
            ));
        }
        Ok(())
    }
}

impl Process for ContainerDNAT {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        if self.rules.is_some() {
            debug!(ctx.logger, "Process rules";
                o!("part" => "container_dnat"));
            self.rules.process(ctx)
        } else {
            trace!(ctx.logger, "No rules";
                    o!("part" => "container_dnat"));
            Ok(None)
        }
    }
}

impl Process for ContainerDNATRule {
    fn process(&self, ctx: &ProcessContext) -> Result<Option<Vec<String>>> {
        debug!(ctx.logger, "Process rule";
                   o!("part" => "container_dnat",
                      "rule" => format!("{:?}", self)));
        let mut rules = Vec::new();
        for expose_port in &self.expose_port {
            let mut nft_rule = RuleBuilder::default();

            if let Some(ref network) = self.src_network {
                if let Some(network) = ctx.network_map.get(network) {
                    trace!(ctx.logger, "Got network";
                               o!("network_name" => &network.name,
                                  "network" => format!("{:?}", network)));

                    let bridge_name = get_bridge_name(&network.id)?;
                    trace!(ctx.logger, "Got bridge name";
                               o!("network_name" => &network.name,
                                  "bridge_name" => &bridge_name));

                    nft_rule.in_interface(&bridge_name);

                    if let Some(ref src_container) = self.src_container {
                        if let Some(src_network) = get_network_for_container(
                            ctx.docker,
                            &ctx.container_map,
                            src_container,
                            &network.id,
                        )? {
                            trace!(ctx.logger, "Got source network";
                                       o!("network_name" => &network.name,
                                          "src_network" => format!("{:?}", src_network)));

                            let bridge_name = get_bridge_name(&network.id)?;
                            trace!(ctx.logger, "Got bridge name";
                                       o!("network_name" => &network.name,
                                          "bridge_name" => &bridge_name));

                            nft_rule.in_interface(&bridge_name).source_address(
                                src_network
                                    .ipv4_address
                                    .split('/')
                                    .next()
                                    .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                            );
                        }
                    }
                }
            }

            let network = match ctx.network_map.get(&self.dst_network) {
                Some(network) => network,
                None => return Ok(None),
            };
            let dst_network = match get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                &self.dst_container,
                &network.id,
            )? {
                Some(dst_network) => dst_network,
                None => return Ok(None),
            };
            trace!(ctx.logger, "Got destination network";
                       o!("network_name" => &network.name,
                          "dst_network" => format!("{:?}", dst_network)));

            let bridge_name = get_bridge_name(&network.id)?;
            trace!(ctx.logger, "Got bridge name";
                       o!("network_name" => &network.name,
                          "bridge_name" => &bridge_name));

            nft_rule.out_interface(&bridge_name);

            let destination_port = match expose_port.container_port {
                Some(destination_port) => destination_port.to_string(),
                None => expose_port.host_port.to_string(),
            };
            nft_rule.destination_port(&destination_port);
            nft_rule.dnat(&format!(
                "{}:{}",
                dst_network
                    .ipv4_address
                    .split('/')
                    .next()
                    .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                destination_port
            ));

            let rule = nft_rule.build()?;
            debug!(ctx.logger, "Add prerouting rule";
                       o!("part" => "container_dnat",
                          "rule" => &rule));

            // Apply the rule
            rules.push(nftables::add_rule(Family::Ip, "dfw", "prerouting", &rule));
            // TODO: verify what is needed for ipt6
        }

        Ok(Some(rules))
    }
}

/// Enclosing struct to manage rule processing.
pub struct ProcessContext<'a> {
    docker: &'a Docker,
    dfw: &'a DFW,
    container_map: Map<String, Container>,
    network_map: Map<String, NetworkDetails>,
    external_network_interfaces: Option<Vec<String>>,
    primary_external_network_interface: Option<String>,
    logger: Logger,
    dry_run: bool,
    current_ruleset: Option<String>,
}

impl<'a> ProcessContext<'a> {
    /// Create a new instance of `ProcessDFW` for rule processing.
    pub fn new(
        docker: &'a Docker,
        dfw: &'a DFW,
        processing_options: &'a ProcessingOptions,
        logger: &'a Logger,
        dry_run: bool,
    ) -> Result<ProcessContext<'a>> {
        let logger = logger.new(o!());

        let container_list_options = match processing_options.container_filter {
            ContainerFilter::All => Default::default(),
            ContainerFilter::Running => ContainerListOptions::builder()
                .filter(vec![ContainerFilterShiplift::Status("running".to_owned())])
                .build(),
        };
        let containers = docker.containers().list(&container_list_options).sync()?;
        debug!(logger, "Got list of containers";
               o!("containers" => format!("{:#?}", containers)));

        let container_map =
            get_container_map(&containers)?.ok_or_else(|| format_err!("no containers found"))?;
        trace!(logger, "Got map of containers";
               o!("container_map" => format!("{:#?}", container_map)));

        let networks = docker.networks().list(&Default::default()).sync()?;
        debug!(logger, "Got list of networks";
               o!("networks" => format!("{:#?}", networks)));

        let network_map =
            get_network_map(&networks)?.ok_or_else(|| format_err!("no networks found"))?;
        trace!(logger, "Got map of networks";
               o!("container_map" => format!("{:#?}", container_map)));

        let external_network_interfaces = dfw
            .defaults
            .as_ref()
            .and_then(|d| d.external_network_interfaces.as_ref())
            .cloned();
        let primary_external_network_interface = external_network_interfaces
            .as_ref()
            .and_then(|v| v.get(0))
            .map(|s| s.to_owned());

        let current_ruleset = Self::get_current_ruleset().ok();

        Ok(ProcessContext {
            docker,
            dfw,
            container_map,
            network_map,
            external_network_interfaces,
            primary_external_network_interface,
            logger,
            dry_run,
            current_ruleset,
        })
    }

    /// Start the processing using the configuration given at creation.
    pub fn process(&mut self) -> Result<()> {
        if let Some(rules) = self.dfw.process(self)? {
            if self.dry_run {
                info!(self.logger, "Performing dry-run, will not update any rules");
            } else {
                // To atomically update the ruleset, we need to write a file and pass that to `nft -f`.
                let rule_file = tempfile::Builder::new().tempfile()?;
                let rule_file_path = rule_file.as_ref().as_os_str().to_os_string();
                debug!(self.logger, "Writing rules to temporary file";
                       o!("file_path" => rule_file_path.to_string_lossy().into_owned()));
                let mut writer = BufWriter::new(rule_file);

                for rule in rules {
                    writeln!(writer, "{}", rule)?;
                }
                writer.flush()?;
                trace!(self.logger, "Finished writing rules to temporary file");

                info!(self.logger, "Applying rules (using nft)");
                let output = Command::new("nft").arg("-f").arg(rule_file_path).output()?;
                if !output.status.success() {
                    return Err(DFWError::NFTablesError {
                        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                    }
                    .into());
                } else {
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    /// Check if the provided string-marker is part of the current ruleset (if available).
    pub fn marker_in_current_ruleset(&self, marker: &str) -> bool {
        self.current_ruleset
            .as_ref()
            .map(|current_ruleset| current_ruleset.contains(marker))
            .unwrap_or(false)
    }

    fn get_current_ruleset() -> Result<String> {
        let output = Command::new("nft").args(&["list", "ruleset"]).output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Option to filter the containers to be processed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerFilter {
    /// Process all containers, i.e. don't filter.
    All,
    /// Only process running containers.
    Running,
}

/// Options to configure the processing procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingOptions {
    /// Option to filter the containers to be processed, see
    /// [`ContainerFilter`](enum.ContainerFilter.html).
    pub container_filter: ContainerFilter,
}

impl Default for ProcessingOptions {
    fn default() -> Self {
        ProcessingOptions {
            container_filter: ContainerFilter::All,
        }
    }
}

fn get_bridge_name(network_id: &str) -> Result<String> {
    if network_id.len() < 12 {
        bail!("network has to be longer than 12 characters");
    }
    Ok(format!("br-{}", &network_id[..12]))
}

fn get_network_for_container(
    docker: &Docker,
    container_map: &Map<String, Container>,
    container_name: &str,
    network_id: &str,
) -> Result<Option<NetworkContainerDetails>> {
    Ok(match container_map.get(container_name) {
        Some(container) => match docker
            .networks()
            .get(network_id)
            .inspect()
            .sync()?
            .containers
            .get(&container.id)
        {
            Some(network) => Some(network.clone()),
            None => None,
        },
        None => None,
    })
}

fn get_container_map(containers: &[Container]) -> Result<Option<Map<String, Container>>> {
    let mut container_map: Map<String, Container> = Map::new();
    for container in containers {
        for name in &container.names {
            container_map.insert(
                name.clone().trim_start_matches('/').to_owned(),
                container.clone(),
            );
        }
    }

    if container_map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(container_map))
    }
}

fn get_network_map(networks: &[NetworkDetails]) -> Result<Option<Map<String, NetworkDetails>>> {
    let mut network_map: Map<String, NetworkDetails> = Map::new();
    for network in networks {
        network_map.insert(network.name.clone(), network.clone());
    }

    if network_map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(network_map))
    }
}

fn generate_marker(components: &[&str]) -> String {
    format!("DFW-MARKER:{}", components.join(";"))
}
