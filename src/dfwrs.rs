//! DFWRS

use std::collections::HashMap as Map;

use boondock::{ContainerListOptions, Docker};
use boondock::container::Container;
use boondock::container::Network as ContainerNetwork;
use iptables::IPTables;

use docker::*;
use errors::*;
use types::*;

const DFWRS_CTC_CHAIN: &'static str = "DFWRS_FORWARD";

pub fn process(docker: &Docker, dfw: &DFW, ipt4: &IPTables, ipt6: &IPTables) -> Result<()> {
    // TODO: external_network_interface
    if let Some(ref init) = dfw.initialization {
        process_initialization(init, dfw, ipt4, ipt6)?;
    }
    // TODO: container_to_container
    if let Some(ref ctc) = dfw.container_to_container {
        process_container_to_container(docker, ctc, dfw, ipt4, ipt6)?;
    }
    // TODO: container_to_wider_world
    // TODO: container_to_host
    // TODO: wider_world_to_container
    // TODO: container_dnat

    Ok(())
}

fn process_initialization(init: &Initialization,
                          _dfw: &DFW,
                          ipt4: &IPTables,
                          ipt6: &IPTables)
                          -> Result<()> {
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
                                  _dfw: &DFW,
                                  ipt4: &IPTables,
                                  ipt6: &IPTables)
                                  -> Result<()> {

    // Create and flush CTC chain
    ipt4.new_chain("filter", DFWRS_CTC_CHAIN)?;
    ipt6.new_chain("filter", DFWRS_CTC_CHAIN)?;
    ipt4.flush_chain("filter", DFWRS_CTC_CHAIN)?;
    ipt6.flush_chain("filter", DFWRS_CTC_CHAIN)?;

    let containers = docker.containers(ContainerListOptions::default().all())?;
    let container_map = get_container_map(&containers)?;

    if ctc.rules.is_some() && container_map.is_some() {
        process_ctc_rules(docker,
                          &ctc.rules.as_ref().unwrap(),
                          container_map.unwrap(),
                          ipt4,
                          ipt6)?;
    }

    // Add default policy as a rule
    ipt4.append("filter", DFWRS_CTC_CHAIN, "-j DROP")?;
    ipt6.append("filter", DFWRS_CTC_CHAIN, "-j DROP")?;

    Ok(())
}

fn process_ctc_rules(docker: &Docker,
                     rules: &Vec<ContainerToContainerRule>,
                     container_map: Map<String, &Container>,
                     ipt4: &IPTables,
                     _ipt6: &IPTables)
                     -> Result<()> {
    for rule in rules {
        println!("{:#?}", rule);
        let mut args: Vec<String> = Vec::new();
        let mut src_network_device_name: Option<String> = None;

        // TODO: refactor into `get_network` (issue #14)
        // Push arguments in regards to the source network
        if let Some(ref src_container) = rule.src_container {
            // Check if `src_container` exists
            if !container_map.contains_key(src_container) {
                continue;
            }
            let container_info = docker.container_info(container_map.get(src_container).unwrap())?;

            // Get `ContainerNetwork` for `src_container` which matches the `network` in `rule`
            let container_networks = &container_info.NetworkSettings.Networks;
            if !container_networks.contains_key(&rule.network) {
                continue;
            }
            let src_network: &ContainerNetwork = container_networks.get(&rule.network).unwrap();

            // Create the rule
            args.push("-i".to_owned());
            let bridge_name = format!("br-{}", &src_network.NetworkID[..12]);
            args.push(bridge_name.clone());

            args.push("-s".to_owned());
            args.push(src_network.IPAddress.clone());

            src_network_device_name = Some(bridge_name.clone())
        }

        // Push arguments in regards to the destination network
        if let Some(ref dst_container) = rule.dst_container {
            // Check if `dst_container` exists
            if !container_map.contains_key(dst_container) {
                continue;
            }
            let container_info = docker.container_info(container_map.get(dst_container).unwrap())?;

            // Get `ContainerNetwork` for `dst_container` which matches the `network` in `rule`
            let container_networks = &container_info.NetworkSettings.Networks;
            if !container_networks.contains_key(&rule.network) {
                continue;
            }
            let dst_network: &ContainerNetwork = container_networks.get(&rule.network).unwrap();

            // Create the rule
            args.push("-o".to_owned());
            args.push(format!("br-{}", &dst_network.NetworkID[..12]));

            args.push("-d".to_owned());
            args.push(dst_network.IPAddress.clone());
        } else {
            // If there is no destination network but there was a source network, push that again
            if let Some(device_name) = src_network_device_name {
                args.push("-o".to_owned());
                args.push(device_name);
            }
        }

        // Push the action
        args.push("-j".to_owned());
        args.push(rule.action.clone());

        // Apply the rule
        ipt4.append("filter", DFWRS_CTC_CHAIN, &args.join(" "))?;
        // TODO: verify that the same is needed for ipt6
    }

    Ok(())
}
