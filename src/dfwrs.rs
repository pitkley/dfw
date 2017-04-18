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
    pub filter: Option<String>,
    pub jump: Option<String>,
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

    pub fn filter(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.filter = Some(value);
        new
    }

    pub fn jump(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.jump = Some(value);
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
        if let Some(ref filter) = self.filter {
            args.push(filter.to_owned());
        }

        // Bail if none of the above was initialized
        if args.len() <= 0 {
            bail!("one of `source`, `destination`, `in_interface`, `out_interface` \
                   or `filter` must be initialized");
        }

        if let Some(ref protocol) = self.protocol {
            args.push("-p".to_owned());
            args.push(protocol.to_owned());
        }

        if let Some(ref jump) = self.jump {
            args.push("-j".to_owned());
            args.push(jump.to_owned());
        } else {
            bail!("`jump` must be initialized");
        }

        Ok(args.join(" "))
    }
}

pub fn process(docker: &Docker, dfw: &DFW, ipt4: &IPTables, ipt6: &IPTables) -> Result<()> {
    let containers = docker.containers(ContainerListOptions::default().all())?;
    let container_map = get_container_map(&containers)?;
    let networks = docker.networks()?;
    let network_map = get_network_map(&networks)?;

    create_and_flush_chain(DFWRS_FORWARD_CHAIN, ipt4, ipt6)?;

    // TODO: external_network_interface
    println!("\n==> process_initialization\n");
    if let Some(ref init) = dfw.initialization {
        process_initialization(init, ipt4, ipt6)?;
    }
    // TODO: container_to_container
    println!("\n\n==> process_container_to_container\n");
    if let Some(ref ctc) = dfw.container_to_container {
        process_container_to_container(docker,
                                       ctc,
                                       container_map.as_ref(),
                                       network_map.as_ref(),
                                       ipt4,
                                       ipt6)?;
    }
    // TODO: container_to_wider_world
    println!("\n\n==> process_container_to_wider_world\n");
    if let Some(ref ctww) = dfw.container_to_wider_world {
        process_container_to_wider_world(docker,
                                         ctww,
                                         dfw.external_network_interface.as_ref(),
                                         container_map.as_ref(),
                                         network_map.as_ref(),
                                         ipt4,
                                         ipt6)?;
    }
    // TODO: container_to_host
    // TODO: wider_world_to_container
    // TODO: container_dnat

    // Set default policy for forward chain (defined by `container_to_container`)
    if let Some(ref ctc) = dfw.container_to_container {
        ipt4.append("filter",
                    DFWRS_FORWARD_CHAIN,
                    &format!("-j {}", ctc.default_policy))?;
        // TODO: verify what is needed for ipt6
    }

    Ok(())
}

fn create_and_flush_chain(chain: &str, ipt4: &IPTables, ipt6: &IPTables) -> Result<()> {
    // Create and flush CTC chain
    ipt4.new_chain("filter", chain)?;
    ipt6.new_chain("filter", chain)?;
    ipt4.flush_chain("filter", chain)?;
    ipt6.flush_chain("filter", chain)?;

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
                                  container_map: Option<&Map<String, &Container>>,
                                  network_map: Option<&Map<String, &Network>>,
                                  ipt4: &IPTables,
                                  ipt6: &IPTables)
                                  -> Result<()> {
    if ctc.rules.is_some() && container_map.is_some() && network_map.is_some() {
        process_ctc_rules(docker,
                          &ctc.rules.as_ref().unwrap(),
                          container_map.unwrap(),
                          network_map.unwrap(),
                          ipt4,
                          ipt6)?;
    }

    Ok(())
}

fn process_ctc_rules(docker: &Docker,
                     rules: &Vec<ContainerToContainerRule>,
                     container_map: &Map<String, &Container>,
                     network_map: &Map<String, &Network>,
                     ipt4: &IPTables,
                     ipt6: &IPTables)
                     -> Result<()> {
    for rule in rules {
        println!("{:#?}", rule);
        let mut ipt_rule = Rule::default();

        let network = match network_map.get(&rule.network) {
            Some(network) => network,
            None => continue,
        };
        let bridge_name = get_bridge_name(&network.Id)?;
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

            let bridge_name = get_bridge_name(&src_network.NetworkID)?;
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

            let bridge_name = get_bridge_name(&dst_network.NetworkID)?;
            ipt_rule
                .out_interface(bridge_name.to_owned())
                .destination(dst_network.IPAddress.to_owned());
        }

        // Set jump
        ipt_rule.jump(rule.action.to_owned());

        let rule_str = ipt_rule.build()?;
        println!("{:#?}", rule_str);

        // Apply the rule
        ipt4.append("filter", DFWRS_FORWARD_CHAIN, &rule_str)?;
        // TODO: verify what is needed for ipt6
    }

    Ok(())
}

fn process_container_to_wider_world(docker: &Docker,
                                    ctww: &ContainerToWiderWorld,
                                    external_network_interface: Option<&String>,
                                    container_map: Option<&Map<String, &Container>>,
                                    network_map: Option<&Map<String, &Network>>,
                                    ipt4: &IPTables,
                                    ipt6: &IPTables)
                                    -> Result<()> {
    // Rules
    if ctww.rules.is_some() && container_map.is_some() && network_map.is_some() {
        process_ctww_rules(docker,
                           &ctww.rules.as_ref().unwrap(),
                           external_network_interface,
                           container_map.unwrap(),
                           network_map.unwrap(),
                           ipt4,
                           ipt6)?;
    }

    // Default policy
    if network_map.is_some() && external_network_interface.is_some() {
        let network_map = network_map.unwrap();
        let external_network_interface = external_network_interface.unwrap();

        for (_, network) in network_map {
            let bridge_name = get_bridge_name(&network.Id)?;
            let rule = Rule::default()
                .in_interface(bridge_name)
                .out_interface(external_network_interface.to_owned())
                .jump(ctww.default_policy.to_owned())
                .build()?;

            println!("{:?}", rule);
            ipt4.append("filter", DFWRS_FORWARD_CHAIN, &rule)?;
            // TODO: verify what is needed for ipt6
        }
    }

    Ok(())
}

fn process_ctww_rules(docker: &Docker,
                      rules: &Vec<ContainerToWiderWorldRule>,
                      external_network_interface: Option<&String>,
                      container_map: &Map<String, &Container>,
                      network_map: &Map<String, &Network>,
                      ipt4: &IPTables,
                      ipt6: &IPTables)
                      -> Result<()> {
    for rule in rules {
        println!("{:#?}", rule);
        let mut ipt_rule = Rule::default();

        if let Some(ref network) = rule.network {
            if let Some(network) = network_map.get(network) {
                let bridge_name = get_bridge_name(&network.Id)?;
                ipt_rule.in_interface(bridge_name.to_owned());
            }

            if let Some(ref src_container) = rule.src_container {
                if let Some(ref src_network) =
                    get_network_for_container(src_container, network, docker, &container_map)? {
                    let bridge_name = get_bridge_name(&src_network.NetworkID)?;
                    ipt_rule
                        .in_interface(bridge_name.to_owned())
                        .source(src_network.IPAddress.to_owned());
                }
            }
        }

        if let Some(ref filter) = rule.filter {
            ipt_rule.filter(filter.to_owned());
        }

        ipt_rule.jump(rule.action.to_owned());

        // Try to build the rule without the out_interface defined to see if any of the other
        // mandatory fields has been populated.
        ipt_rule.build()?; // TODO: maybe add a `verify` method to `Rule`

        if let Some(ref external_network_interface) = rule.external_network_interface {
            ipt_rule.out_interface(external_network_interface.to_owned());
        } else if let Some(ref external_network_interface) = external_network_interface {
            ipt_rule.out_interface(external_network_interface.to_owned().to_owned());
        }

        let rule_str = ipt_rule.build()?;
        println!("{:#?}", rule_str);

        // Apply the rule
        ipt4.append("filter", DFWRS_FORWARD_CHAIN, &rule_str)?;
        // TODO: verify what is needed for ipt6
    }

    Ok(())
}

fn get_bridge_name(network_id: &str) -> Result<String> {
    if network_id.len() < 12 {
        bail!("network has to be longer than 12 characters");
    }
    Ok(format!("br-{}", &network_id[..12]))
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
