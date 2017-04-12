//! DFWRS

use std::collections::HashMap as Map;

use iptables::IPTables;

use errors::*;
use types::*;

pub fn process(dfw: &DFW, ipt4: IPTables, ipt6: IPTables) -> Result<()> {
    // TODO: external_network_interface
    // TODO: initialization
    if let Some(ref init) = dfw.initialization {
        process_initialization(init, dfw, ipt4, ipt6)?;
    }
    // TODO: container_to_container
    if let Some(ref ctc) = dfw.container_to_container {
        process_container_to_container(ctc, dfw, ipt4, ipt6)?;
    }
    // TODO: container_to_wider_world
    // TODO: container_to_host
    // TODO: wider_world_to_container
    // TODO: container_dnat

    Ok(())
}

fn process_initialization(init: &Map<String, Vec<String>>,
                          _dfw: &DFW,
                          ipt4: IPTables,
                          ipt6: IPTables)
                          -> Result<()> {
    for (table, rules) in init.iter() {
        println!("table: {}", table);
        for rule in rules {
            println!("  RULE: {}", rule);
        }
    }

    Ok(())
}

fn process_container_to_container(ctc: &ContainerToContainer,
                                  _dfw: &DFW,
                                  ipt4: IPTables,
                                  ipt6: IPTables)
                                  -> Result<()> {
    Ok(())
}
