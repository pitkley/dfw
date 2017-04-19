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
const DFWRS_INPUT_CHAIN: &'static str = "DFWRS_INPUT";
const DFWRS_PREROUTING_CHAIN: &'static str = "DFWRS_PREROUTING";

#[derive(Debug, Clone, Default)]
struct Rule {
    pub source: Option<String>,
    pub destination: Option<String>,

    pub in_interface: Option<String>,
    pub out_interface: Option<String>,

    pub not_in_interface: bool,
    pub not_out_interface: bool,

    pub protocol: Option<String>,
    pub source_port: Option<String>,
    pub destination_port: Option<String>,

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

    pub fn not_in_interface(&mut self, value: bool) -> &mut Self {
        let mut new = self;
        new.not_in_interface = value;
        new
    }

    pub fn not_out_interface(&mut self, value: bool) -> &mut Self {
        let mut new = self;
        new.not_out_interface = value;
        new
    }

    pub fn protocol(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.protocol = Some(value);
        new
    }

    pub fn source_port(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.source_port = Some(value);
        new
    }

    pub fn destination_port(&mut self, value: String) -> &mut Self {
        let mut new = self;
        new.destination_port = Some(value);
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
            if self.not_in_interface {
                args.push("!".to_owned());
            }
            args.push("-i".to_owned());
            args.push(in_interface.to_owned());
        }
        if let Some(ref out_interface) = self.out_interface {
            if self.not_out_interface {
                args.push("!".to_owned());
            }
            args.push("-o".to_owned());
            args.push(out_interface.to_owned());
        }

        // Bail if none of the above was initialized
        if args.len() <= 0 && self.filter.is_none() {
            bail!("one of `source`, `destination`, `in_interface`, `out_interface` \
                   or `filter` must be initialized");
        }

        if let Some(ref protocol) = self.protocol {
            args.push("-p".to_owned());
            args.push(protocol.to_owned());
        } else if self.source_port.is_some() || self.destination_port.is_some() {
            // Source and destination ports require that the protocol is set.
            // If it hasn't been specified explicitly, use "tcp" as default.
            args.push("-p".to_owned());
            args.push("tcp".to_owned());
        }

        if let Some(ref source_port) = self.source_port {
            args.push("--sport".to_owned());
            args.push(source_port.to_owned());
        }

        if let Some(ref destination_port) = self.destination_port {
            args.push("--dport".to_owned());
            args.push(destination_port.to_owned());
        }

        if let Some(ref jump) = self.jump {
            args.push("-j".to_owned());
            args.push(jump.to_owned());
        } else {
            bail!("`jump` must be initialized");
        }

        if let Some(ref filter) = self.filter {
            args.push(filter.to_owned());
        }

        Ok(args.join(" "))
    }
}

pub fn process(docker: &Docker, dfw: &DFW, ipt4: &IPTables, ipt6: &IPTables) -> Result<()> {
    let containers = docker.containers(ContainerListOptions::default().all())?;
    let container_map = get_container_map(&containers)?;
    let networks = docker.networks()?;
    let network_map = get_network_map(&networks)?;

    create_and_flush_chain("filter", DFWRS_FORWARD_CHAIN, ipt4, ipt6)?;
    initialize_chain("filter", DFWRS_FORWARD_CHAIN, ipt4, ipt6)?;
    create_and_flush_chain("filter", DFWRS_INPUT_CHAIN, ipt4, ipt6)?;
    initialize_chain("filter", DFWRS_INPUT_CHAIN, ipt4, ipt6)?;
    create_and_flush_chain("nat", DFWRS_PREROUTING_CHAIN, ipt4, ipt6)?;

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
    println!("\n\n==> process_container_to_host\n");
    if let Some(ref cth) = dfw.container_to_host {
        process_container_to_host(docker,
                                  cth,
                                  container_map.as_ref(),
                                  network_map.as_ref(),
                                  ipt4,
                                  ipt6)?;
    }
    // TODO: wider_world_to_container
    println!("\n\n==> process_wider_world_to_container\n");
    if let Some(ref wwtc) = dfw.wider_world_to_container {
        process_wider_world_to_container(docker,
                                         wwtc,
                                         dfw.external_network_interface.as_ref(),
                                         container_map.as_ref(),
                                         network_map.as_ref(),
                                         ipt4,
                                         ipt6)?;
    }
    // TODO: container_dnat
    println!("\n\n==> process_container_dnat\n");
    if let Some(ref cd) = dfw.container_dnat {
        process_container_dnat(docker,
                               cd,
                               dfw.external_network_interface.as_ref(),
                               container_map.as_ref(),
                               network_map.as_ref(),
                               ipt4,
                               ipt6)?;
    }

    // Add accept rules for Docker bridge
    if let Some(ref external_network_interface) = dfw.external_network_interface {
        if let Some(network_map) = network_map {
            if let Some(bridge_network) = network_map.get("bridge") {
                if let Some(bridge_name) =
                    bridge_network
                        .Options
                        .get("com.docker.network.bridge.name") {
                    println!("bridge_name: {}", bridge_name);
                    let rule_str = Rule::default()
                        .in_interface(bridge_name.to_owned())
                        .out_interface(external_network_interface.to_owned())
                        .jump("ACCEPT".to_owned())
                        .build()?;
                    println!("accept-rule: {}", rule_str);
                    ipt4.append("filter", DFWRS_FORWARD_CHAIN, &rule_str)?;
                    // TODO: verify what is needed for ipt6

                    let rule_str = Rule::default()
                        .in_interface(bridge_name.to_owned())
                        .jump("ACCEPT".to_owned())
                        .build()?;
                    ipt4.append("filter", DFWRS_INPUT_CHAIN, &rule_str)?;
                    // TODO: verify what is needed for ipt6
                }
            }
        }
    }

    // Set default policy for forward chain (defined by `container_to_container`)
    if let Some(ref ctc) = dfw.container_to_container {
        ipt4.append("filter",
                    DFWRS_FORWARD_CHAIN,
                    &format!("-j {}", ctc.default_policy))?;
        // TODO: verify what is needed for ipt6
    }

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

fn process_container_to_host(docker: &Docker,
                             cth: &ContainerToHost,
                             container_map: Option<&Map<String, &Container>>,
                             network_map: Option<&Map<String, &Network>>,
                             ipt4: &IPTables,
                             ipt6: &IPTables)
                             -> Result<()> {
    // Rules
    if cth.rules.is_some() && container_map.is_some() && network_map.is_some() {
        process_cth_rules(docker,
                          &cth.rules.as_ref().unwrap(),
                          container_map.unwrap(),
                          network_map.unwrap(),
                          ipt4,
                          ipt6)?;
    }

    // Default policy
    if network_map.is_some() {
        let network_map = network_map.unwrap();

        for (_, network) in network_map {
            let bridge_name = get_bridge_name(&network.Id)?;
            let rule = Rule::default()
                .in_interface(bridge_name)
                .jump(cth.default_policy.to_owned())
                .build()?;

            println!("{:?}", rule);
            ipt4.append("filter", DFWRS_INPUT_CHAIN, &rule)?;
            // TODO: verify what is needed for ipt6
        }
    }

    Ok(())
}

fn process_cth_rules(docker: &Docker,
                     rules: &Vec<ContainerToHostRule>,
                     container_map: &Map<String, &Container>,
                     network_map: &Map<String, &Network>,
                     ipt4: &IPTables,
                     ipt6: &IPTables)
                     -> Result<()> {
    for rule in rules {
        println!("{:#?}", rule);
        let mut ipt_rule = Rule::default();

        if let Some(network) = network_map.get(&rule.network) {
            let bridge_name = get_bridge_name(&network.Id)?;
            ipt_rule.in_interface(bridge_name.to_owned());
        } else {
            // Network has to exist
            continue;
        }

        if let Some(ref src_container) = rule.src_container {
            if let Some(ref src_network) =
                get_network_for_container(src_container, &rule.network, docker, &container_map)? {
                ipt_rule.source(src_network.IPAddress.to_owned());
            }
        }

        if let Some(ref filter) = rule.filter {
            ipt_rule.filter(filter.to_owned());
        }

        ipt_rule.jump(rule.action.to_owned());

        // Try to build the rule without the out_interface defined to see if any of the other
        // mandatory fields has been populated.
        ipt_rule.build()?; // TODO: maybe add a `verify` method to `Rule`

        let rule_str = ipt_rule.build()?;
        println!("{:#?}", rule_str);

        // Apply the rule
        ipt4.append("filter", DFWRS_INPUT_CHAIN, &rule_str)?;
        // TODO: verify what is needed for ipt6
    }

    Ok(())
}

fn process_wider_world_to_container(docker: &Docker,
                                    wwtc: &WiderWorldToContainer,
                                    external_network_interface: Option<&String>,
                                    container_map: Option<&Map<String, &Container>>,
                                    network_map: Option<&Map<String, &Network>>,
                                    ipt4: &IPTables,
                                    ipt6: &IPTables)
                                    -> Result<()> {
    if wwtc.rules.is_none() || container_map.is_none() || network_map.is_none() {
        return Ok(());
    }
    let rules = wwtc.rules.as_ref().unwrap();
    let container_map = container_map.unwrap();
    let network_map = network_map.unwrap();

    for rule in rules {
        println!("{:#?}", rule);
        let mut ipt_forward_rule = Rule::default();
        let mut ipt_dnat_rule = Rule::default();

        if let Some(network) = network_map.get(&rule.network) {
            let bridge_name = get_bridge_name(&network.Id)?;
            ipt_forward_rule.out_interface(bridge_name.to_owned());
        } else {
            // Network has to exist
            continue;
        }

        if let Some(ref dst_network) =
            get_network_for_container(&rule.dst_container, &rule.network, docker, &container_map)? {
            ipt_forward_rule.destination(dst_network.IPAddress.to_owned());

            let destination_port = match rule.expose_port.container_port {
                Some(destination_port) => destination_port.to_string(),
                None => rule.expose_port.host_port.to_string(),
            };
            ipt_forward_rule.destination_port(destination_port.to_owned());
            ipt_dnat_rule.destination_port(destination_port.to_owned());
            ipt_dnat_rule.filter(format!("--to-destination {}:{}",
                                         dst_network.IPAddress,
                                         destination_port));

        } else {
            // Network for container has to exist
            continue;
        }

        ipt_forward_rule.jump("ACCEPT".to_owned());
        ipt_dnat_rule.jump("DNAT".to_owned());

        // Try to build the rule without the out_interface defined to see if any of the other
        // mandatory fields has been populated.
        ipt_forward_rule.build()?; // TODO: maybe add a `verify` method to `Rule`
        ipt_dnat_rule.build()?; // TODO: maybe add a `verify` method to `Rule`

        if let Some(ref external_network_interface) = rule.external_network_interface {
            ipt_forward_rule.in_interface(external_network_interface.to_owned());
            ipt_dnat_rule.in_interface(external_network_interface.to_owned());
        } else if let Some(ref external_network_interface) = external_network_interface {
            ipt_forward_rule.in_interface(external_network_interface.to_owned().to_owned());
            ipt_dnat_rule.in_interface(external_network_interface.to_owned().to_owned());
        } else {
            // The DNAT rule requires the external interface
            continue;
        }

        let forward_rule_str = ipt_forward_rule.build()?;
        println!("{:#?}", forward_rule_str);
        let dnat_rule_str = ipt_dnat_rule.build()?;
        println!("{:#?}", dnat_rule_str);

        // Apply the rule
        ipt4.append("filter", DFWRS_FORWARD_CHAIN, &forward_rule_str)?;
        ipt4.append("nat", DFWRS_PREROUTING_CHAIN, &dnat_rule_str)?;
        // TODO: verify what is needed for ipt6
    }

    Ok(())
}

fn process_container_dnat(docker: &Docker,
                          cd: &ContainerDNAT,
                          external_network_interface: Option<&String>,
                          container_map: Option<&Map<String, &Container>>,
                          network_map: Option<&Map<String, &Network>>,
                          ipt4: &IPTables,
                          ipt6: &IPTables)
                          -> Result<()> {
    if cd.rules.is_none() || container_map.is_none() || network_map.is_none() {
        return Ok(());
    }
    let rules = cd.rules.as_ref().unwrap();
    let container_map = container_map.unwrap();
    let network_map = network_map.unwrap();

    for rule in rules {
        println!("{:#?}", rule);
        let mut ipt_rule = Rule::default();

        if let Some(ref network) = rule.src_network {
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

        if let Some(ref dst_network) =
            get_network_for_container(&rule.dst_container,
                                      &rule.dst_network,
                                      docker,
                                      &container_map)? {
            let destination_port = match rule.expose_port.container_port {
                Some(destination_port) => destination_port.to_string(),
                None => rule.expose_port.host_port.to_string(),
            };
            ipt_rule.destination_port(destination_port.to_owned());
            ipt_rule.filter(format!("--to-destination {}:{}",
                                    dst_network.IPAddress,
                                    destination_port));

        } else {
            // Network for container has to exist
            continue;
        }

        ipt_rule.jump("DNAT".to_owned());

        // Try to build the rule without the out_interface defined to see if any of the other
        // mandatory fields has been populated.
        ipt_rule.build()?; // TODO: maybe add a `verify` method to `Rule`

        if ipt_rule.out_interface.is_none() {
            if let Some(ref external_network_interface) = external_network_interface {
                ipt_rule
                    .in_interface(external_network_interface.to_owned().to_owned())
                    .not_in_interface(true);
            } else {
                // We need to specify a external network interface.
                // If it is not defined, skip the rule.
                continue;
            }
        }

        let rule_str = ipt_rule.build()?;
        println!("{:#?}", rule_str);

        // Apply the rule
        ipt4.append("nat", DFWRS_PREROUTING_CHAIN, &rule_str)?;
        // TODO: verify what is needed for ipt6
    }

    Ok(())
}

fn create_and_flush_chain(table: &str,
                          chain: &str,
                          ipt4: &IPTables,
                          ipt6: &IPTables)
                          -> Result<()> {
    // Create and flush CTC chain
    ipt4.new_chain(table, chain)?;
    ipt6.new_chain(table, chain)?;
    ipt4.flush_chain(table, chain)?;
    ipt6.flush_chain(table, chain)?;

    Ok(())
}

fn initialize_chain(table: &str, chain: &str, ipt4: &IPTables, ipt6: &IPTables) -> Result<()> {
    // Drop INVALID, accept RELATED/ESTABLISHED
    ipt4.append(table, chain, "-m state --state INVALID -j DROP")?;
    ipt6.append(table, chain, "-m state --state INVALID -j DROP")?;
    ipt4.append(table,
                chain,
                "-m state --state RELATED,ESTABLISHED -j ACCEPT")?;
    ipt6.append(table,
                chain,
                "-m state --state RELATED,ESTABLISHED -j ACCEPT")?;

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
