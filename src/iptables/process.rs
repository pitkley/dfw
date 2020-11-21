// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

use super::{
    rule::{BuiltRule, Rule},
    Iptables, IptablesRule, IptablesRuleDiscriminants, PolicyOrRule, DFW_FORWARD_CHAIN,
    DFW_INPUT_CHAIN, DFW_POSTROUTING_CHAIN, DFW_PREROUTING_CHAIN,
};
use crate::{errors::*, process::*, types::*, FirewallBackend};
use failure::{format_err, ResultExt};
use slog::{debug, info, o, trace};

impl Process<Iptables> for DFW<Iptables> {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        info!(ctx.logger, "Starting processing";
              o!("started_processing_at" => time::OffsetDateTime::now_utc().format("%FT%T%z")));
        let mut rules = vec![
            new_chain(IptablesRuleDiscriminants::V4, "filter", DFW_FORWARD_CHAIN),
            flush_chain(IptablesRuleDiscriminants::V4, "filter", DFW_FORWARD_CHAIN),
            new_chain(IptablesRuleDiscriminants::V6, "filter", DFW_FORWARD_CHAIN),
            flush_chain(IptablesRuleDiscriminants::V6, "filter", DFW_FORWARD_CHAIN),
            new_chain(IptablesRuleDiscriminants::V4, "filter", DFW_INPUT_CHAIN),
            flush_chain(IptablesRuleDiscriminants::V4, "filter", DFW_INPUT_CHAIN),
            new_chain(IptablesRuleDiscriminants::V6, "filter", DFW_INPUT_CHAIN),
            flush_chain(IptablesRuleDiscriminants::V6, "filter", DFW_INPUT_CHAIN),
            new_chain(IptablesRuleDiscriminants::V4, "nat", DFW_POSTROUTING_CHAIN),
            flush_chain(IptablesRuleDiscriminants::V4, "nat", DFW_POSTROUTING_CHAIN),
            new_chain(IptablesRuleDiscriminants::V6, "nat", DFW_POSTROUTING_CHAIN),
            flush_chain(IptablesRuleDiscriminants::V6, "nat", DFW_POSTROUTING_CHAIN),
            new_chain(IptablesRuleDiscriminants::V4, "nat", DFW_PREROUTING_CHAIN),
            flush_chain(IptablesRuleDiscriminants::V4, "nat", DFW_PREROUTING_CHAIN),
            new_chain(IptablesRuleDiscriminants::V6, "nat", DFW_PREROUTING_CHAIN),
            flush_chain(IptablesRuleDiscriminants::V6, "nat", DFW_PREROUTING_CHAIN),
            append_rule(
                IptablesRuleDiscriminants::V4,
                "filter",
                DFW_INPUT_CHAIN,
                "-m state --state INVALID -j DROP",
            ),
            append_rule(
                IptablesRuleDiscriminants::V6,
                "filter",
                DFW_INPUT_CHAIN,
                "-m state --state INVALID -j DROP",
            ),
            append_rule(
                IptablesRuleDiscriminants::V4,
                "filter",
                DFW_INPUT_CHAIN,
                "-m state --state RELATED,ESTABLISHED -j ACCEPT",
            ),
            append_rule(
                IptablesRuleDiscriminants::V6,
                "filter",
                DFW_INPUT_CHAIN,
                "-m state --state RELATED,ESTABLISHED -j ACCEPT",
            ),
            append_rule(
                IptablesRuleDiscriminants::V4,
                "filter",
                "INPUT",
                &format!("-j {}", DFW_INPUT_CHAIN),
            ),
            set_policy(IptablesRuleDiscriminants::V4, "filter", "INPUT", "-"),
            append_rule(
                IptablesRuleDiscriminants::V4,
                "filter",
                DFW_FORWARD_CHAIN,
                "-m state --state INVALID -j DROP",
            ),
            append_rule(
                IptablesRuleDiscriminants::V6,
                "filter",
                DFW_FORWARD_CHAIN,
                "-m state --state INVALID -j DROP",
            ),
            append_rule(
                IptablesRuleDiscriminants::V4,
                "filter",
                DFW_FORWARD_CHAIN,
                "-m state --state RELATED,ESTABLISHED -j ACCEPT",
            ),
            append_rule(
                IptablesRuleDiscriminants::V6,
                "filter",
                DFW_FORWARD_CHAIN,
                "-m state --state RELATED,ESTABLISHED -j ACCEPT",
            ),
            append_rule(
                IptablesRuleDiscriminants::V4,
                "filter",
                "FORWARD",
                &format!("-j {}", DFW_FORWARD_CHAIN),
            ),
            set_policy(IptablesRuleDiscriminants::V4, "filter", "FORWARD", "-"),
            append_rule(
                IptablesRuleDiscriminants::V4,
                "nat",
                "PREROUTING",
                &format!("-j {}", DFW_PREROUTING_CHAIN),
            ),
            set_policy(IptablesRuleDiscriminants::V4, "nat", "PREROUTING", "-"),
            append_rule(
                IptablesRuleDiscriminants::V4,
                "nat",
                "POSTROUTING",
                &format!("-j {}", DFW_POSTROUTING_CHAIN),
            ),
            set_policy(IptablesRuleDiscriminants::V4, "nat", "POSTROUTING", "-"),
        ];
        for sub_rules in vec![
            self.backend_defaults.process(ctx)?,
            self.container_to_container.process(ctx)?,
            self.container_to_wider_world.process(ctx)?,
            self.container_to_host.process(ctx)?,
            self.wider_world_to_container.process(ctx)?,
            self.container_dnat.process(ctx)?,
            self.global_defaults.process(ctx)?,
        ] {
            if let Some(mut sub_rules) = sub_rules {
                rules.append(&mut sub_rules);
            }
        }

        info!(ctx.logger, "Finished processing";
              o!("finished_processing_at" => time::OffsetDateTime::now_utc().format("%FT%T%z")));

        Ok(Some(rules))
    }
}

impl Process<Iptables> for <Iptables as FirewallBackend>::Defaults {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        debug!(ctx.logger, "Starting sub-processing";
               o!("part" => "backend_defaults"));
        let mut rules = Vec::new();

        if let Some(initialization) = &self.initialization {
            if let Some(v4) = &initialization.v4 {
                debug!(ctx.logger, "Process initialization rules";
                       o!("ip" => "v4"));
                for (table, initialization_rules) in v4.iter() {
                    debug!(ctx.logger, "Process table";
                           o!("ip" => "v4",
                              "table" => table));
                    for rule in initialization_rules {
                        debug!(ctx.logger, "Process rule";
                               o!("ip" => "v4",
                                  "table" => table,
                                  "rule" => rule));
                        rules.push(add_rule(IptablesRuleDiscriminants::V4, table, rule));
                        trace!(ctx.logger, "Rule added";
                               o!("ip" => "v4",
                                  "table" => table,
                                  "rule" => rule))
                    }
                }
            }

            if let Some(v6) = &initialization.v6 {
                debug!(ctx.logger, "Process initialization rules";
                       o!("ip" => "v6"));
                for (table, initialization_rules) in v6.iter() {
                    debug!(ctx.logger, "Process table";
                           o!("ip" => "v6",
                              "table" => table));
                    for rule in initialization_rules {
                        debug!(ctx.logger, "Process rule";
                               o!("ip" => "v6",
                                  "table" => table,
                                  "rule" => rule));
                        rules.push(add_rule(IptablesRuleDiscriminants::V6, table, rule));
                        trace!(ctx.logger, "Rule added";
                               o!("ip" => "v6",
                                  "table" => table,
                                  "rule" => rule))
                    }
                }
            }
        }

        Ok(Some(rules))
    }
}

impl Process<Iptables> for GlobalDefaults {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        debug!(ctx.logger, "Starting sub-processing";
               o!("part" => "global_defaults"));
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
                let rule = Rule::new("filter", DFW_INPUT_CHAIN)
                    .in_interface(bridge_name)
                    .jump("ACCEPT")
                    .build()?;
                rules.push(append_built_rule(IptablesRuleDiscriminants::V4, &rule));

                // Set policy for forward-chain, divided by the external network interfaces.
                if let Some(ref external_network_interfaces) = self.external_network_interfaces {
                    for external_network_interface in external_network_interfaces {
                        let rule = Rule::new("filter", DFW_FORWARD_CHAIN)
                            .in_interface(bridge_name)
                            .out_interface(external_network_interface)
                            .jump("ACCEPT")
                            .build()?;
                        rules.push(append_built_rule(IptablesRuleDiscriminants::V4, &rule));
                    }
                }
            }
        }

        // Configure postrouting
        if let Some(ref external_network_interfaces) = self.external_network_interfaces {
            for external_network_interface in external_network_interfaces {
                // Configure postrouting
                let rule = Rule::new("nat", DFW_POSTROUTING_CHAIN)
                    .out_interface(external_network_interface)
                    .jump("MASQUERADE")
                    .build()?;
                rules.push(append_built_rule(IptablesRuleDiscriminants::V4, &rule));
            }
        }

        Ok(Some(rules))
    }
}

impl Process<Iptables> for ContainerToContainer {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        debug!(ctx.logger, "Starting sub-processing";
               o!("part" => "container_to_container"));
        let mut rules = Vec::new();

        if let Some(mut ctc_rules) = self.rules.process(ctx)? {
            rules.append(&mut ctc_rules);
        }

        // Enforce default policy for container-to-container communication.
        rules.push(append_rule(
            IptablesRuleDiscriminants::V4,
            "filter",
            DFW_FORWARD_CHAIN,
            &format!("-j {}", self.default_policy.to_string().to_uppercase()),
        ));

        Ok(Some(rules))
    }
}

impl Process<Iptables> for ContainerToContainerRule {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        trace!(ctx.logger, "Processing rule";
               o!("part" => "container_to_container_rule",
                  "rule" => format!("{:?}", self)));
        let mut ipt_rule = Rule::new("filter", DFW_FORWARD_CHAIN);

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

        ipt_rule
            .in_interface(&bridge_name)
            .out_interface(&bridge_name);

        if let Some(ref src_container) = self.src_container {
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

            ipt_rule
                .in_interface(&bridge_name)
                .out_interface(&bridge_name)
                .source(
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

            ipt_rule.out_interface(&bridge_name).destination(
                dst_network
                    .ipv4_address
                    .split('/')
                    .next()
                    .ok_or_else(|| format_err!("IPv4 address is empty"))?,
            );
        }

        if let Some(ref filter) = self.matches {
            ipt_rule.filter(filter);
        }

        // Set jump
        ipt_rule.jump(&self.verdict.to_string().to_uppercase());

        let rule = ipt_rule.build()?;
        debug!(ctx.logger, "Add forward rule";
               o!("part" => "container_to_container",
                  "rule" => &rule.rule));

        Ok(Some(vec![append_built_rule(
            IptablesRuleDiscriminants::V4,
            &rule,
        )]))
    }
}

impl Process<Iptables> for ContainerToWiderWorld {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        debug!(ctx.logger, "Starting sub-processing";
               o!("part" => "container_to_wider_world"));
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

                    let rule = Rule::new("filter", DFW_FORWARD_CHAIN)
                        .in_interface(&bridge_name)
                        .out_interface(external_network_interface)
                        .jump(&self.default_policy.to_string().to_uppercase())
                        .build()?;

                    debug!(ctx.logger, "Add forward rule for default policy";
                           o!("part" => "container_to_wider_world",
                              "external_network_interface" => external_network_interface,
                              "default_policy" => &self.default_policy,
                              "rule" => &rule));

                    rules.push(append_built_rule(IptablesRuleDiscriminants::V4, &rule));
                }
            }
        }

        Ok(Some(rules))
    }
}

impl Process<Iptables> for ContainerToWiderWorldRule {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        trace!(ctx.logger, "Process rule";
               o!("part" => "container_to_wider_world_rule",
                  "rule" => format!("{:?}", self)));

        let mut ipt_rule = Rule::new("filter", DFW_FORWARD_CHAIN);

        if let Some(ref network) = self.network {
            if let Some(network) = ctx.network_map.get(network) {
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

                        ipt_rule.in_interface(&bridge_name).source(
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

                    ipt_rule.in_interface(&bridge_name);
                }
            }
        }

        if let Some(ref filter) = self.matches {
            ipt_rule.filter(filter);
        }

        ipt_rule.jump(&self.verdict.to_string().to_uppercase());

        // Try to build the rule without the out_interface defined to see if all of the other
        // mandatory fields has been populated.
        debug!(ctx.logger, "Build rule to verify contents";
               o!("args" => format!("{:?}", ipt_rule)));
        ipt_rule.build().context(format!(
            "failed to build rule, maybe the network `{:?}` or container `{:?}` doesn't exist",
            self.network, self.src_container
        ))?;

        if let Some(ref external_network_interface) = self.external_network_interface {
            trace!(ctx.logger, "Rule has specific external network interface";
                   o!("external_network_interface" => external_network_interface));
            ipt_rule.out_interface(external_network_interface);
        } else if let Some(ref primary_external_network_interface) =
            ctx.primary_external_network_interface
        {
            trace!(ctx.logger, "Rule uses primary external network interface";
                   o!("external_network_interface" => primary_external_network_interface));
            ipt_rule.out_interface(primary_external_network_interface);
        }

        let rule = ipt_rule.build()?;
        debug!(ctx.logger, "Add forward rule";
               o!("part" => "container_to_wider_world",
                  "rule" => &rule.rule));

        Ok(Some(vec![append_built_rule(
            IptablesRuleDiscriminants::V4,
            &rule,
        )]))
    }
}

impl Process<Iptables> for ContainerToHost {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        debug!(ctx.logger, "Starting sub-processing";
               o!("part" => "container_to_host"));
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

            let rule = Rule::new("filter", DFW_INPUT_CHAIN)
                .in_interface(&bridge_name)
                .jump(&self.default_policy.to_string().to_uppercase())
                .build()?;

            trace!(ctx.logger, "Add input rule for default policy";
                   o!("part" => "container_to_host",
                      "default_policy" => self.default_policy,
                      "rule" => &rule));
            rules.push(append_built_rule(IptablesRuleDiscriminants::V4, &rule));
        }

        Ok(Some(rules))
    }
}

impl Process<Iptables> for ContainerToHostRule {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        trace!(ctx.logger, "Process rule";
               o!("part" => "container_to_host_rule",
                  "rule" => format!("{:?}", self)));
        let mut ipt_rule = Rule::new("filter", DFW_INPUT_CHAIN);

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

        ipt_rule.in_interface(&bridge_name);

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
                ipt_rule.source(
                    src_network
                        .ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                );
            }
        }

        if let Some(ref filter) = self.matches {
            ipt_rule.filter(filter);
        }

        ipt_rule.jump(&self.verdict.to_string().to_uppercase());

        // Try to build the rule without the out_interface defined to see if all of the other
        // mandatory fields has been populated.
        debug!(ctx.logger, "Build rule to verify contents";
               o!("args" => format!("{:?}", ipt_rule)));
        ipt_rule.build().context(format!(
            "failed to build rule, maybe the container `{:?}` doesn't exist",
            self.src_container
        ))?;

        let rule = ipt_rule.build()?;
        debug!(ctx.logger, "Add input rule";
               o!("part" => "container_to_host",
                  "rule" => &rule));

        Ok(Some(vec![append_built_rule(
            IptablesRuleDiscriminants::V4,
            &rule,
        )]))
    }
}

impl Process<Iptables> for WiderWorldToContainer {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        debug!(ctx.logger, "Starting sub-processing";
               o!("part" => "wider_world_to_container"));
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

impl Process<Iptables> for WiderWorldToContainerRule {
    #[allow(clippy::cognitive_complexity)]
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        trace!(ctx.logger, "Process rule";
               o!("part" => "wider_world_to_container_rule",
                  "rule" => format!("{:?}", self)));
        let mut rules = Vec::new();

        for expose_port in &self.expose_port {
            let mut ipt_forward_rule = Rule::new("filter", DFW_FORWARD_CHAIN);
            let mut ipt_dnat_rule = Rule::new("nat", DFW_PREROUTING_CHAIN);
            let mut ipt6_input_rule = Rule::new("filter", DFW_INPUT_CHAIN);

            let network = match ctx.network_map.get(&self.network) {
                Some(network) => network,
                None => continue,
            };
            trace!(ctx.logger, "Got network";
                   o!("network_name" => &network.name,
                      "network" => format!("{:?}", network)));

            let bridge_name = get_bridge_name(&network.id)?;
            trace!(ctx.logger, "Got bridge name";
                   o!("network_name" => &network.name,
                      "bridge_name" => &bridge_name));

            ipt_forward_rule.out_interface(&bridge_name);

            if let Some(dst_network) = get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                &self.dst_container,
                &network.id,
            )? {
                trace!(ctx.logger, "Got destination network";
                       o!("network_name" => &network.name,
                          "dst_network" => format!("{:?}", dst_network)));

                ipt_forward_rule.destination(
                    dst_network
                        .ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                );

                let host_port = expose_port.host_port.to_string();
                let container_port = match expose_port.container_port {
                    Some(destination_port) => destination_port.to_string(),
                    None => expose_port.host_port.to_string(),
                };
                ipt_forward_rule.destination_port(&container_port);
                ipt_dnat_rule.destination_port(&host_port);
                ipt_dnat_rule.jump(&format!(
                    "DNAT --to-destination {}:{}",
                    dst_network
                        .ipv4_address
                        .split('/')
                        .next()
                        .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                    container_port
                ));
                ipt6_input_rule.destination_port(&host_port);
            } else {
                // Network for container has to exist
                continue;
            }

            // Set correct protocol
            ipt_forward_rule.protocol(&expose_port.family);
            ipt_dnat_rule.protocol(&expose_port.family);
            ipt6_input_rule.protocol(&expose_port.family);

            ipt_forward_rule.jump("ACCEPT");
            ipt6_input_rule.jump("ACCEPT");

            // Try to build the rule without the out_interface defined to see if any of the
            // other mandatory fields has been populated.
            debug!(ctx.logger, "Build rule to verify contents";
                   o!("args" => format!("{:?}", ipt_forward_rule)));
            ipt_forward_rule.build()?;
            debug!(ctx.logger, "Build rule to verify contents";
                   o!("args" => format!("{:?}", ipt_dnat_rule)));
            ipt_dnat_rule.build()?;

            if let Some(ref external_network_interface) = self.external_network_interface {
                trace!(ctx.logger, "Rule has specific external network interface";
                       o!("external_network_interface" => external_network_interface));

                ipt_forward_rule.in_interface(external_network_interface);
                ipt_dnat_rule.in_interface(external_network_interface);
            } else if let Some(ref primary_external_network_interface) =
                ctx.primary_external_network_interface
            {
                trace!(ctx.logger, "Rule uses primary external network interface";
                       o!("external_network_interface" => primary_external_network_interface));

                ipt_forward_rule.in_interface(primary_external_network_interface);
                ipt_dnat_rule.in_interface(primary_external_network_interface);
                ipt6_input_rule.in_interface(primary_external_network_interface);
            } else {
                // The DNAT rule requires the external interface
                continue;
            }

            // If source CIDRs have been specified, create the FORWARD-rules as required to
            // restrict the traffic as intended.
            if let Some(source_cidrs) = &self.source_cidr_v4 {
                debug!(ctx.logger, "Generate extended FORWARD rules, source CIDRs were specified";
                       o!("args" => format!("{:?}", ipt_dnat_rule),
                          "source_cidrs" => source_cidrs.join(", ")));
                for additional_forward_rule in source_cidrs
                    .iter()
                    .map(|source_cidr| {
                        let mut forward_rule = ipt_forward_rule.clone();
                        forward_rule.source(source_cidr);
                        forward_rule
                    })
                    .map(|forward_rule| forward_rule.build())
                    .collect::<Result<Vec<_>>>()?
                {
                    debug!(ctx.logger, "Add FORWARD rule";
                           o!("part" => "wider_world_to_container",
                              "rule" => &additional_forward_rule.rule));
                    rules.push(append_built_rule(
                        IptablesRuleDiscriminants::V4,
                        &additional_forward_rule,
                    ));
                }
                for additional_dnat_rule in source_cidrs
                    .iter()
                    .map(|source_cidr| {
                        let mut dnat_rule = ipt_dnat_rule.clone();
                        dnat_rule.source(source_cidr);
                        dnat_rule
                    })
                    .map(|dnat_rule| dnat_rule.build())
                    .collect::<Result<Vec<_>>>()?
                {
                    debug!(ctx.logger, "Add DNAT rule";
                           o!("part" => "wider_world_to_container",
                              "rule" => &additional_dnat_rule.rule));
                    rules.push(append_built_rule(
                        IptablesRuleDiscriminants::V4,
                        &additional_dnat_rule,
                    ));
                }
            } else {
                let forward_rule = ipt_forward_rule.build()?;
                debug!(ctx.logger, "Add forward rule";
                       o!("part" => "wider_world_to_container",
                          "rule" => &forward_rule.rule));
                let dnat_rule = ipt_dnat_rule.build()?;
                debug!(ctx.logger, "Add DNAT rule";
                       o!("part" => "wider_world_to_container",
                          "rule" => &dnat_rule.rule));
                // Apply the rule
                rules.push(append_built_rule(
                    IptablesRuleDiscriminants::V4,
                    &forward_rule,
                ));
                rules.push(append_built_rule(IptablesRuleDiscriminants::V4, &dnat_rule));
            }
            if self.expose_via_ipv6 {
                if let Some(source_cidrs) = &self.source_cidr_v6 {
                    for additional_input_rule in source_cidrs
                        .iter()
                        .map(|source_cidr| {
                            let mut input_rule = ipt6_input_rule.clone();
                            input_rule.source(source_cidr);
                            input_rule
                        })
                        .map(|input_rule| input_rule.build())
                        .collect::<Result<Vec<_>>>()?
                    {
                        debug!(ctx.logger, "Add IPv6 INPUT rule";
                               o!("part" => "wider_world_to_container",
                                   "rule" => &additional_input_rule.rule));
                        rules.push(append_built_rule(
                            IptablesRuleDiscriminants::V6,
                            &additional_input_rule,
                        ));
                    }
                } else {
                    let input_rule = ipt6_input_rule.build()?;
                    debug!(ctx.logger, "Add IPv6 INPUT rule";
                           o!("part" => "wider_world_to_container",
                               "rule" => &input_rule.rule));
                    rules.push(append_built_rule(
                        IptablesRuleDiscriminants::V6,
                        &input_rule,
                    ));
                }
            }
        }

        Ok(Some(rules))
    }
}

impl Process<Iptables> for ContainerDNAT {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        debug!(ctx.logger, "Starting sub-processing";
               o!("part" => "container_dnat"));
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

impl Process<Iptables> for ContainerDNATRule {
    fn process(&self, ctx: &ProcessContext<Iptables>) -> Result<Option<Vec<IptablesRule>>> {
        trace!(ctx.logger, "Process rule";
               o!("part" => "container_dnat_rule",
                  "rule" => format!("{:?}", self)));
        let mut rules = Vec::new();
        for expose_port in &self.expose_port {
            let mut ipt_rule = Rule::new("nat", DFW_PREROUTING_CHAIN);

            if let Some(ref network) = self.src_network {
                if let Some(network) = ctx.network_map.get(network) {
                    trace!(ctx.logger, "Got network";
                           o!("network_name" => &network.name,
                              "network" => format!("{:?}", network)));

                    let bridge_name = get_bridge_name(&network.id)?;
                    trace!(ctx.logger, "Got bridge name";
                           o!("network_name" => &network.name,
                              "bridge_name" => &bridge_name));

                    ipt_rule.in_interface(&bridge_name);

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

                            ipt_rule.in_interface(&bridge_name).source(
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
                None => continue,
            };
            let dst_network = match get_network_for_container(
                ctx.docker,
                &ctx.container_map,
                &self.dst_container,
                &network.id,
            )? {
                Some(dst_network) => dst_network,
                None => continue,
            };
            trace!(ctx.logger, "Got destination network";
                   o!("network_name" => &network.name,
                      "dst_network" => format!("{:?}", dst_network)));

            let bridge_name = get_bridge_name(&network.id)?;
            trace!(ctx.logger, "Got bridge name";
                   o!("network_name" => &network.name,
                      "bridge_name" => &bridge_name));

            ipt_rule.out_interface(&bridge_name);

            let destination_port = match expose_port.container_port {
                Some(destination_port) => destination_port.to_string(),
                None => expose_port.host_port.to_string(),
            };
            ipt_rule.destination_port(&destination_port);
            ipt_rule.jump(&format!(
                "DNAT --to-destination {}:{}",
                dst_network
                    .ipv4_address
                    .split('/')
                    .next()
                    .ok_or_else(|| format_err!("IPv4 address is empty"))?,
                destination_port
            ));

            // Try to build the rule without the out_interface defined to see if any of the
            // other mandatory fields has been populated.
            debug!(ctx.logger, "Build rule to verify contents";
                   o!("args" => format!("{:?}", ipt_rule)));
            ipt_rule.build()?;

            if ipt_rule.out_interface.is_none() {
                if let Some(ref primary_external_network_interface) =
                    ctx.primary_external_network_interface
                {
                    trace!(ctx.logger, "Set primary external network interface";
                           o!("external_network_interface"
                              => primary_external_network_interface));

                    ipt_rule
                        .in_interface(primary_external_network_interface)
                        .not_in_interface(true);
                } else {
                    // We need to specify a external network interface.
                    // If it is not defined, skip the rule.
                    continue;
                }
            }

            let rule = ipt_rule.build()?;
            debug!(ctx.logger, "Add prerouting rule";
                   o!("part" => "container_dnat",
                      "rule" => &rule.rule));

            rules.push(append_built_rule(IptablesRuleDiscriminants::V4, &rule));
        }

        Ok(Some(rules))
    }
}

fn set_policy(
    rule_discriminant: IptablesRuleDiscriminants,
    table: &str,
    chain: &str,
    policy: &str,
) -> IptablesRule {
    IptablesRule::from_discriminant(
        rule_discriminant,
        PolicyOrRule::Policy {
            table: table.to_owned(),
            chain: chain.to_owned(),
            policy: policy.to_owned(),
        },
    )
}

fn new_chain(
    rule_discriminant: IptablesRuleDiscriminants,
    table: &str,
    chain: &str,
) -> IptablesRule {
    set_policy(rule_discriminant, table, chain, "-")
}

fn flush_chain(
    rule_discriminant: IptablesRuleDiscriminants,
    table: &str,
    chain: &str,
) -> IptablesRule {
    IptablesRule::from_discriminant(
        rule_discriminant,
        PolicyOrRule::Rule {
            table: table.to_owned(),
            chain: chain.to_owned(),
            value: format!("-F {}", chain),
        },
    )
}

fn add_rule(rule_discriminant: IptablesRuleDiscriminants, table: &str, rule: &str) -> IptablesRule {
    IptablesRule::from_discriminant(
        rule_discriminant,
        PolicyOrRule::Rule {
            table: table.to_owned(),
            chain: "".to_owned(),
            value: rule.to_owned(),
        },
    )
}

fn append_rule(
    rule_discriminant: IptablesRuleDiscriminants,
    table: &str,
    chain: &str,
    rule: &str,
) -> IptablesRule {
    IptablesRule::from_discriminant(
        rule_discriminant,
        PolicyOrRule::Rule {
            table: table.to_owned(),
            chain: chain.to_owned(),
            value: format!("-A {} {}", chain, rule),
        },
    )
}

fn append_built_rule(
    rule_discriminant: IptablesRuleDiscriminants,
    rule: &BuiltRule,
) -> IptablesRule {
    append_rule(rule_discriminant, &*rule.table, &*rule.chain, &*rule.rule)
}
