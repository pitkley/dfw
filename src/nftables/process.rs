// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

use super::{
    rule::RuleBuilder, Family, Hook, Nftables, Type, DFW_MARK, NF_PRIORITY_INET_FILTER_ANY_DFW,
    NF_PRIORITY_IP6_NAT_POSTROUTING_DFW, NF_PRIORITY_IP6_NAT_PREROUTING_DFW,
    NF_PRIORITY_IP_NAT_POSTROUTING_DFW, NF_PRIORITY_IP_NAT_PREROUTING_DFW,
};
use crate::{errors::*, process::*, types::*, FirewallBackend};
use failure::{format_err, ResultExt};
use slog::{debug, info, o, trace, warn};
use std::process::Command;
use time::format_description::well_known::Rfc3339;

impl Process<Nftables> for DFW<Nftables> {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
        info!(ctx.logger, "Starting processing";
              o!("started_processing_at" => time::OffsetDateTime::now_utc().format(&Rfc3339).expect("failed to format time")));
        let mut rules = vec![
            add_table(Family::Inet, "dfw"),
            flush_table(Family::Inet, "dfw"),
            add_base_chain(
                Family::Inet,
                "dfw",
                "input",
                Type::Filter,
                Hook::Input,
                NF_PRIORITY_INET_FILTER_ANY_DFW,
            ),
            add_rule(Family::Inet, "dfw", "input", "ct state invalid drop"),
            add_rule(
                Family::Inet,
                "dfw",
                "input",
                "ct state { related, established } accept",
            ),
            add_base_chain(
                Family::Inet,
                "dfw",
                "forward",
                Type::Filter,
                Hook::Forward,
                NF_PRIORITY_INET_FILTER_ANY_DFW,
            ),
            add_rule(Family::Inet, "dfw", "forward", "ct state invalid drop"),
            add_rule(
                Family::Inet,
                "dfw",
                "forward",
                "ct state { related, established } accept",
            ),
            add_table(Family::Ip, "dfw"),
            flush_table(Family::Ip, "dfw"),
            add_base_chain(
                Family::Ip,
                "dfw",
                "prerouting",
                Type::Nat,
                Hook::Prerouting,
                NF_PRIORITY_IP_NAT_PREROUTING_DFW,
            ),
            add_base_chain(
                Family::Ip,
                "dfw",
                "postrouting",
                Type::Nat,
                Hook::Postrouting,
                NF_PRIORITY_IP_NAT_POSTROUTING_DFW,
            ),
            add_table(Family::Ip6, "dfw"),
            flush_table(Family::Ip6, "dfw"),
            add_base_chain(
                Family::Ip6,
                "dfw",
                "prerouting",
                Type::Nat,
                Hook::Prerouting,
                NF_PRIORITY_IP6_NAT_PREROUTING_DFW,
            ),
            add_base_chain(
                Family::Ip6,
                "dfw",
                "postrouting",
                Type::Nat,
                Hook::Postrouting,
                NF_PRIORITY_IP6_NAT_POSTROUTING_DFW,
            ),
        ];
        for mut sub_rules in vec![
            self.backend_defaults
                .clone()
                .or_else(|| {
                    // NOTE: this is only required to retain backwards compatibility for version
                    // <1.2. This can be removed in major-version 2 (hence the conditional
                    // compile-error).
                    #[cfg(not(crate_major_version = "1"))]
                    compile_error!("remove this workaround with version 2");

                    Some(Default::default())
                })
                .process(ctx)?,
            self.global_defaults.process(ctx)?,
            self.container_to_container.process(ctx)?,
            self.container_to_wider_world.process(ctx)?,
            self.container_to_host.process(ctx)?,
            self.wider_world_to_container.process(ctx)?,
            self.container_dnat.process(ctx)?,
        ]
        .into_iter()
        .flatten()
        {
            rules.append(&mut sub_rules);
        }

        info!(ctx.logger, "Finished processing";
              o!("finished_processing_at" => time::OffsetDateTime::now_utc().format(&Rfc3339).expect("failed to format time")));

        Ok(Some(rules))
    }
}

impl Process<Nftables> for <Nftables as FirewallBackend>::Defaults {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
        // NOTE: v1.2.0 deprecated the `nftables::types::Defaults::rules` field in favour of the
        // field present in the `Initialization` sub-type. To retain backwards-compatibility we
        // allow the old field to be present and we will use it if the new field was not specified.
        // (We also warn the user if they used the deprecated field.)
        let mut rules = self
            .initialization
            .clone()
            .and_then(|initialization| initialization.rules)
            .or_else(|| {
                #[cfg_attr(crate_major_version = "1", allow(deprecated))]
                ctx.dfw
                    .initialization
                    .as_ref()
                    .and_then(|initialization| initialization.rules.clone())
                    .filter(|_| {
                        warn!(
                            ctx.logger,
                            "You are using the deprecated `initialization.rules` field in your \
                                configuration! This field has been replaced by the \
                                `backend_defaults.initialization.rules` field. The value format of the \
                                field has stayed unchanged, which means that moving the field to the new \
                                section is sufficient to fix this warning.";
                            o!("deprecated_field" => "initialization.rules",
                                "deprecated_since" => "1.2.0",
                                "planned_removal_in" => "2.0.0",
                                "new_field" => "backend_defaults.initialization.rules",
                                "field_value_format_changed" => false));
                        true
                    })
            })
            .unwrap_or_default();

        // NOTE: v1.2.0 deprecated the `GlobalDefaults::custom_tables` field in favour of the field
        // present in the backend-specific defaults-type. To retain backwards-compatibility we
        // allow the old field to be present and we will use it if the backend-specific field was
        // not specified. (We also warn the user if they used the deprecated field.)
        #[cfg_attr(crate_major_version = "1", allow(deprecated))]
        let custom_tables = self.custom_tables.as_ref().or_else(|| {
            ctx.dfw.global_defaults.custom_tables.as_ref().filter(|_| {
                warn!(
                        ctx.logger,
                        "You are using the deprecated `global_defaults.custom_tables` field in \
                         your configuration! This field has been replaced by the \
                         `backend_defaults.custom_tables` field. The value format of the field has \
                         stayed unchanged, which means that moving the field to the new section is \
                         sufficient to fix this warning.";
                        o!("deprecated_field" => "global_defaults.custom_tables",
                           "deprecated_since" => "1.2.0",
                           "planned_removal_in" => "2.0.0",
                           "new_field" => "backend_defaults.custom_tables",
                           "field_value_format_changed" => false));
                true
            })
        });

        // Hook into other chains if requested
        if let Some(custom_tables) = custom_tables {
            // Retrieve current ruleset to avoid duplication of already existing rules.
            let current_ruleset = Command::new("nft")
                .args(["list", "ruleset"])
                .output()
                .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
                .ok();

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
                            if !current_ruleset
                                .as_ref()
                                .map(|current_ruleset| current_ruleset.contains(&marker))
                                .unwrap_or(false)
                            {
                                additional_rules.push(insert_rule(
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

        Ok(Some(rules))
    }
}

impl Process<Nftables> for GlobalDefaults {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();

        // Enforce policy for default Docker-bridge (usually docker0) to access host-resources
        if let Some(bridge_network) = ctx.network_map.get("bridge") {
            if let Some(bridge_name) = bridge_network
                .options
                .as_ref()
                .ok_or_else(|| format_err!("couldn't get network options"))?
                .get("com.docker.network.bridge.name")
            {
                // Set policy for input-chain
                rules.push(add_rule(
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
                        rules.push(add_rule(
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
                        ));
                    }
                }
            }
        }

        // Configure postrouting
        if let Some(ref external_network_interfaces) = self.external_network_interfaces {
            for external_network_interface in external_network_interfaces {
                // Configure postrouting
                rules.push(add_rule(
                    Family::Ip,
                    "dfw",
                    "postrouting",
                    &format!(
                        "meta oifname {} meta mark set {} masquerade",
                        external_network_interface, DFW_MARK,
                    ),
                ));
                rules.push(add_rule(
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

impl Process<Nftables> for ContainerToContainer {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
        // Enforce default policy for container-to-container communication.
        let mut rules = vec![set_chain_policy(
            Family::Inet,
            "dfw",
            "forward",
            self.default_policy,
        )];

        if let Some(mut ctc_rules) = self.rules.process(ctx)? {
            rules.append(&mut ctc_rules);
        }

        if let Some(same_network_verdict) = self.same_network_verdict {
            for network in ctx.network_map.values() {
                let bridge_name = get_bridge_name(network)?;
                trace!(ctx.logger, "Got bridge name";
                       o!("network_name" => &network.name,
                          "bridge_name" => &bridge_name));

                let rule = RuleBuilder::default()
                    .in_interface(&bridge_name)
                    .out_interface(&bridge_name)
                    .verdict(same_network_verdict)
                    .build()?;

                debug!(ctx.logger, "Add forward rule for same network verdict for bridge";
                       o!("part" => "container_to_container",
                          "bridge_name" => bridge_name,
                          "same_network_verdict" => same_network_verdict,
                          "rule" => &rule));

                rules.push(add_rule(Family::Inet, "dfw", "forward", &rule));
            }
        }

        Ok(Some(rules))
    }
}

impl Process<Nftables> for ContainerToContainerRule {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();
        let mut nft_rule = RuleBuilder::default();
        let network = match ctx.network_map.get(&self.network) {
            Some(network) => network,
            None => return Ok(None),
        };
        trace!(ctx.logger, "Got network";
                    o!("network_name" => &self.network,
                        "network" => format!("{:?}", network)));
        let network_id = network.id.as_ref().expect("Docker network ID missing");
        let bridge_name = get_bridge_name(network)?;
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
                network_id,
            )? {
                Some(src_network) => src_network,
                None => return Ok(None),
            };
            trace!(ctx.logger, "Got source network";
                        o!("network_name" => &network.name,
                            "src_network" => format!("{:?}", src_network)));

            let bridge_name = get_bridge_name(network)?;
            trace!(ctx.logger, "Got bridge name";
                        o!("network_name" => &network.name,
                            "bridge_name" => &bridge_name));

            nft_rule
                .in_interface(&bridge_name)
                .out_interface(&bridge_name)
                .source_address(
                    src_network
                        .ipv4_address
                        .expect("IPv4 address for container missing")
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
                network_id,
            )? {
                Some(dst_network) => dst_network,
                None => return Ok(None),
            };
            trace!(ctx.logger, "Got destination network";
                        o!("network_name" => &network.name,
                            "dst_network" => format!("{:?}", dst_network)));

            let bridge_name = get_bridge_name(network)?;
            trace!(ctx.logger, "Got bridge name";
                        o!("network_name" => &network.name,
                            "bridge_name" => &bridge_name));

            nft_rule.out_interface(&bridge_name).destination_address(
                dst_network
                    .ipv4_address
                    .expect("IPv4 address for container missing")
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
        rules.push(add_rule(Family::Inet, "dfw", "forward", &rule));

        Ok(Some(rules))
    }
}

impl Process<Nftables> for ContainerToWiderWorld {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
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
                    let bridge_name = get_bridge_name(network)?;
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

                    rules.push(add_rule(Family::Inet, "dfw", "forward", &rule));
                }
            }
        }

        Ok(Some(rules))
    }
}

impl Process<Nftables> for ContainerToWiderWorldRule {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();
        debug!(ctx.logger, "Process rule";
                   o!("part" => "container_to_wider_world",
                      "rule" => format!("{:?}", self)));
        let mut nft_rule = RuleBuilder::default();

        if let Some(ref network) = self.network {
            if let Some(network) = ctx.network_map.get(network) {
                let network_id = network.id.as_ref().expect("Docker network ID missing");
                let bridge_name = get_bridge_name(network)?;
                trace!(ctx.logger, "Got bridge name";
                           o!("network_name" => &network.name,
                              "bridge_name" => &bridge_name));

                nft_rule.in_interface(&bridge_name);

                if let Some(ref src_container) = self.src_container {
                    if let Some(src_network) = get_network_for_container(
                        ctx.docker,
                        &ctx.container_map,
                        src_container,
                        network_id,
                    )? {
                        trace!(ctx.logger, "Got source network";
                                   o!("network_name" => &network.name,
                                      "src_network" => format!("{:?}", src_network)));

                        let bridge_name = get_bridge_name(network)?;
                        trace!(ctx.logger, "Got bridge name";
                                   o!("network_name" => &network.name,
                                      "bridge_name" => &bridge_name));

                        nft_rule.in_interface(&bridge_name).source_address(
                            src_network
                                .ipv4_address
                                .expect("IPv4 address for container missing")
                                .split('/')
                                .next()
                                .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                        );
                    }
                } else {
                    let bridge_name = get_bridge_name(network)?;
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
        rules.push(add_rule(Family::Inet, "dfw", "forward", &rule));
        Ok(Some(rules))
    }
}

impl Process<Nftables> for ContainerToHost {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
        let mut rules = Vec::new();

        if let Some(mut cth_rules) = self.rules.process(ctx)? {
            rules.append(&mut cth_rules);
        }

        // Default policy
        for network in ctx.network_map.values() {
            let bridge_name = get_bridge_name(network)?;
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
            rules.push(add_rule(Family::Inet, "dfw", "input", &rule));
        }

        Ok(Some(rules))
    }
}

impl Process<Nftables> for ContainerToHostRule {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
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

        let network_id = network.id.as_ref().expect("Docker network ID missing");
        let bridge_name = get_bridge_name(network)?;
        trace!(ctx.logger, "Got bridge name";
                   o!("network_name" => &network.name,
                      "bridge_name" => &bridge_name));

        nft_rule.in_interface(&bridge_name);

        if let Some(ref src_container) = self.src_container {
            if let Some(src_network) = get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                src_container,
                network_id,
            )? {
                trace!(ctx.logger, "Got source network";
                           o!("network_name" => &network.name,
                              "src_network" => format!("{:?}", src_network)));
                nft_rule.source_address(
                    src_network
                        .ipv4_address
                        .expect("IPv4 address for container missing")
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
        nft_rule.build().context(format!(
            "failed to build rule, maybe the container `{:?}` doesn't exist",
            self.src_container
        ))?;

        let rule = nft_rule.build()?;
        debug!(ctx.logger, "Add input rule";
                   o!("part" => "container_to_host",
                      "rule" => &rule));

        // Apply the rule
        rules.push(add_rule(Family::Inet, "dfw", "input", &rule));

        Ok(Some(rules))
    }
}

impl Process<Nftables> for WiderWorldToContainer {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
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

impl WiderWorldToContainerRule {
    fn apply_source_cidrs_v4(
        &self,
        ctx: &ProcessContext<Nftables>,
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
            rules.push(add_rule(
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
            rules.push(add_rule(
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
        ctx: &ProcessContext<Nftables>,
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
            rules.push(add_rule(
                Family::Ip6,
                "dfw",
                "prerouting",
                &additional_mark_rule,
            ));
        }
        Ok(())
    }
}

impl Process<Nftables> for WiderWorldToContainerRule {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
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

            let network_id = network.id.as_ref().expect("Docker network ID missing");
            let bridge_name = get_bridge_name(network)?;
            trace!(ctx.logger, "Got bridge name";
                   o!("network_name" => &network.name,
                      "bridge_name" => &bridge_name));

            nft_forward_rule.out_interface(&bridge_name);

            if let Some(dst_network) = get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                &self.dst_container,
                network_id,
            )? {
                trace!(ctx.logger, "Got destination network";
                       o!("network_name" => &network.name,
                          "dst_network" => format!("{:?}", dst_network)));

                let container_ipv4_address = dst_network
                    .ipv4_address
                    .expect("IPv4 address for container missing");
                nft_forward_rule.destination_address(
                    container_ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                );

                let host_port = expose_port.host_port.to_string();
                let container_port = match expose_port.container_port {
                    Some(destination_port) => destination_port.to_string(),
                    None => expose_port.host_port.to_string(),
                };
                nft_forward_rule.destination_port(&container_port);
                nft_dnat_rule.destination_port(&host_port);
                nft_dnat_rule.dnat(&format!(
                    "{}:{}",
                    container_ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                    container_port
                ));
                nft_mark_rule.destination_port(&host_port);
            // INFO: correct IPv6 handling would include actually using IPv6-addresses.
            // While the code below is correct, the postrouting does not work since nftables cannot
            // route IPv6 packets to IPv4 destinations.
            //
            // if !dst_network.ipv6_address.is_empty() {
            //     nft_mark_rule.dnat(&format!(
            //         "{}:{}",
            //         dst_network.ipv6_address
            //         .expect("IPv6 address for container missing")
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
            nft_forward_rule.build()?;
            debug!(ctx.logger, "build rule to verify contents";
                   o!("args" => format!("{:?}", nft_dnat_rule)));
            nft_dnat_rule.build()?;
            debug!(ctx.logger, "Build rule to verify contents";
                   o!("args" => format!("{:?}", nft_mark_rule)));
            nft_mark_rule.build()?;

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
            if self.expose_via_ipv6 {
                if let Some(source_cidrs_v6) = &self.source_cidr_v6 {
                    self.apply_source_cidrs_v6(
                        ctx,
                        &mut rules,
                        source_cidrs_v6,
                        nft_mark_rule.clone(),
                    )?;
                }
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
                rules.push(add_rule(Family::Inet, "dfw", "forward", &forward_rule));
                rules.push(add_rule(Family::Ip, "dfw", "prerouting", &dnat_rule));
                if self.expose_via_ipv6 {
                    rules.push(add_rule(Family::Ip6, "dfw", "prerouting", &mark_rule));
                }
            }
        }

        Ok(Some(rules))
    }
}

impl Process<Nftables> for ContainerDNAT {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
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

impl Process<Nftables> for ContainerDNATRule {
    fn process(&self, ctx: &ProcessContext<Nftables>) -> Result<Option<Vec<String>>> {
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

                    let network_id = network.id.as_ref().expect("Docker network ID missing");
                    let bridge_name = get_bridge_name(network)?;
                    trace!(ctx.logger, "Got bridge name";
                               o!("network_name" => &network.name,
                                  "bridge_name" => &bridge_name));

                    nft_rule.in_interface(&bridge_name);

                    if let Some(ref src_container) = self.src_container {
                        if let Some(src_network) = get_network_for_container(
                            ctx.docker,
                            &ctx.container_map,
                            src_container,
                            network_id,
                        )? {
                            trace!(ctx.logger, "Got source network";
                                       o!("network_name" => &network.name,
                                          "src_network" => format!("{:?}", src_network)));

                            let bridge_name = get_bridge_name(network)?;
                            trace!(ctx.logger, "Got bridge name";
                                       o!("network_name" => &network.name,
                                          "bridge_name" => &bridge_name));

                            nft_rule.in_interface(&bridge_name).source_address(
                                src_network
                                    .ipv4_address
                                    .expect("IPv4 address for container missing")
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
            let network_id = network.id.as_ref().expect("Docker network ID missing");
            let dst_network = match get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                &self.dst_container,
                network_id,
            )? {
                Some(dst_network) => dst_network,
                None => return Ok(None),
            };
            trace!(ctx.logger, "Got destination network";
                       o!("network_name" => &network.name,
                          "dst_network" => format!("{:?}", dst_network)));

            let bridge_name = get_bridge_name(network)?;
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
                    .expect("IPv4 address for container missing")
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
            rules.push(add_rule(Family::Ip, "dfw", "prerouting", &rule));
        }

        Ok(Some(rules))
    }
}

/// Construct nft command for adding a table.
fn add_table(family: Family, table: &str) -> String {
    format!("add table {} {}", family, table)
}

/// Construct nft command for flushing a table.
fn flush_table(family: Family, table: &str) -> String {
    format!("flush table {} {}", family, table)
}

/// Construct nft command for adding a base chain.
fn add_base_chain(
    family: Family,
    table: &str,
    chain: &str,
    r#type: Type,
    hook: Hook,
    priority: i16,
) -> String {
    format!(
        "add chain {} {} {} {{ type {} hook {} priority {} ; }}",
        family, table, chain, r#type, hook, priority
    )
}

/// Construct nft command for setting the policy for a chain.
fn set_chain_policy(family: Family, table: &str, chain: &str, policy: ChainPolicy) -> String {
    format!(
        "add chain {} {} {} {{ policy {} ; }}",
        family, table, chain, policy
    )
}

/// Construct nft command for adding a rule to a chain.
fn add_rule(family: Family, table: &str, chain: &str, rule: &str) -> String {
    format!("add rule {} {} {} {}", family, table, chain, rule)
}

/// Construct nft command for inserting a rule into a chain.
fn insert_rule(
    family: Family,
    table: &str,
    chain: &str,
    rule: &str,
    position: Option<u32>,
) -> String {
    format!(
        "insert rule {} {} {} {}{}",
        family,
        table,
        chain,
        if let Some(position) = position {
            format!("position {} ", position)
        } else {
            "".to_owned()
        },
        rule
    )
}
