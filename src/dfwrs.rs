//! DFWRS

use std::collections::HashMap as Map;

use boondock::{ContainerListOptions, Docker};
use boondock::container::Container;
use boondock::container::Network as ContainerNetwork;
use boondock::network::Network;
use iptables::IPTables;

use docker::*;
use errors::*;
use types::*;

const DFWRS_FORWARD_CHAIN: &'static str = "DFWRS_FORWARD";

#[derive(Debug, Clone, Default)]
struct Rule {
    pub source: Option<String>,
    pub destination: Option<String>,
    pub in_interface: Option<String>,
    pub out_interface: Option<String>,
    pub protocol: Option<String>,
    pub jump: String,
}

#[allow(dead_code)]
impl Rule {
    pub fn source(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.source = Some(value);
        new
    }

    pub fn destination(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.destination = Some(value);
        new
    }

    pub fn in_interface(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.in_interface = Some(value);
        new
    }

    pub fn out_interface(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.out_interface = Some(value);
        new
    }

    pub fn protocol(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.protocol = Some(value);
        new
    }

    pub fn jump(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.jump = value;
        new
    }

    pub fn build(&self) -> Result<String> {
        let mut args: Vec<String> = Vec::new();

        if let Some(ref source) = self.source {
            args.push("-s".to_owned());
            args.push(source.to_owned());
        }
        if let Some(ref destination) = self.destination {
            args.push("-d".to_owned());
            args.push(destination.to_owned());
        }
        if let Some(ref in_interface) = self.in_interface {
            args.push("-i".to_owned());
            args.push(in_interface.to_owned());
        }
        if let Some(ref out_interface) = self.out_interface {
            args.push("-o".to_owned());
            args.push(out_interface.to_owned());
        }
        if let Some(ref protocol) = self.protocol {
            args.push("-p".to_owned());
            args.push(protocol.to_owned());
        }

        args.push("-j".to_owned());
        args.push(self.jump.to_owned());

        Ok(args.join(" "))
    }
}

pub fn process(docker: &Docker, dfw: &DFW, ipt4: &IPTables, ipt6: &IPTables) -> Result<()> {
    // TODO: external_network_interface
    if let Some(ref init) = dfw.initialization {
        process_initialization(init, ipt4, ipt6)?;
    }
    // TODO: container_to_container
    if let Some(ref ctc) = dfw.container_to_container {
        process_container_to_container(docker, ctc, ipt4, ipt6)?;
    }
    // TODO: container_to_wider_world
    // TODO: container_to_host
    // TODO: wider_world_to_container
    // TODO: container_dnat

    Ok(())
}

fn process_initialization(init: &Initialization, ipt4: &IPTables, ipt6: &IPTables) -> Result<()> {
    if let Some(ref v4) = init.v4 {
        for (table, rules) in v4.iter() {
            println!("table: {}", table);
            for rule in rules {
                println!("  RULE: {}", rule);
                let out = ipt4.execute(table, rule)?;
                println!(" status: {:?}", out.status);
            }
        }
    }

    if let Some(ref v6) = init.v6 {
        for (table, rules) in v6.iter() {
            println!("table: {}", table);
            for rule in rules {
                println!("  RULE: {}", rule);
                let out = ipt6.execute(table, rule)?;
                println!(" status: {:?}", out.status);
            }
        }
    }

    Ok(())
}

fn process_container_to_container(docker: &Docker,
                                  ctc: &ContainerToContainer,
                                  ipt4: &IPTables,
                                  ipt6: &IPTables)
                                  -> Result<()> {

    // Create and flush CTC chain
    ipt4.new_chain("filter", DFWRS_FORWARD_CHAIN)?;
    ipt6.new_chain("filter", DFWRS_FORWARD_CHAIN)?;
    ipt4.flush_chain("filter", DFWRS_FORWARD_CHAIN)?;
    ipt6.flush_chain("filter", DFWRS_FORWARD_CHAIN)?;

    let containers = docker.containers(ContainerListOptions::default().all())?;
    let container_map = get_container_map(&containers)?;
    let networks = docker.networks()?;
    let network_map = get_network_map(&networks)?;

    if ctc.rules.is_some() && container_map.is_some() {
        process_ctc_rules(docker,
                          &ctc.rules.as_ref().unwrap(),
                          container_map.unwrap(),
                          network_map.unwrap(),
                          ipt4,
                          ipt6)?;
    }

    // Add default policy as a rule
    // FIXME: this inserts the policy to early, since container_to_wider_world uses the
    // FORWARD-chain too
    ipt4.append("filter", DFWRS_FORWARD_CHAIN, "-j DROP")?;
    ipt6.append("filter", DFWRS_FORWARD_CHAIN, "-j DROP")?;

    Ok(())
}

fn get_network_for_container(container_name: &String,
                             network_name: &String,
                             docker: &Docker,
                             container_map: &Map<String, &Container>)
                             -> Result<Option<ContainerNetwork>> {
    // Check if `container_name` exists
    if !container_map.contains_key(container_name) {
        return Ok(None);
    }
    let container_info = docker
        .container_info(container_map.get(container_name).unwrap())?;

    // Get `ContainerNetwork` which matches the `network_name` for `container_name`
    let container_networks: Map<String, ContainerNetwork> = container_info.NetworkSettings.Networks;
    match container_networks.get(network_name) {
        Some(network) => Ok(Some(network.clone())),
        None => Ok(None),
    }
}

fn process_ctc_rules(docker: &Docker,
                     rules: &Vec<ContainerToContainerRule>,
                     container_map: Map<String, &Container>,
                     network_map: Map<String, &Network>,
                     ipt4: &IPTables,
                     _ipt6: &IPTables)
                     -> Result<()> {
    for rule in rules {
        println!("{:#?}", rule);
        let mut ipt_rule = Rule::default();

        let network = match network_map.get(&rule.network) {
            Some(network) => network,
            None => continue,
        };
        let bridge_name = format!("br-{}", &network.Id[..12]);
        ipt_rule
            .in_interface(bridge_name.to_owned())
            .out_interface(bridge_name.to_owned());

        if let Some(ref src_container) = rule.src_container {
            let src_network = match get_network_for_container(src_container,
                                                              &rule.network,
                                                              docker,
                                                              &container_map)? {
                Some(network) => network,
                None => continue,
            };

            let bridge_name = format!("br-{}", &src_network.NetworkID[..12]);
            ipt_rule
                .in_interface(bridge_name.to_owned())
                .out_interface(bridge_name.to_owned())
                .source(src_network.IPAddress.to_owned());
        }

        if let Some(ref dst_container) = rule.dst_container {
            let dst_network = match get_network_for_container(dst_container,
                                                              &rule.network,
                                                              docker,
                                                              &container_map)? {
                Some(network) => network,
                None => continue,
            };

            let bridge_name = format!("br-{}", &dst_network.NetworkID[..12]);
            ipt_rule
                .out_interface(bridge_name.to_owned())
                .destination(dst_network.IPAddress.to_owned());
        }

        // Set jump
        ipt_rule.jump(rule.action.to_owned());

        // Apply the rule
        ipt4.append("filter", DFWRS_FORWARD_CHAIN, &rule_str)?;
        // TODO: verify what is needed for ipt6
    }

    Ok(())
}
