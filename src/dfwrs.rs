//! DFWRS

use std::collections::HashMap as Map;

use iptables;
use iptables::IPTables;
use shiplift::Docker;
use shiplift::rep::Container;
use shiplift::rep::{NetworkDetails, NetworkContainerDetails};

use errors::*;
use types::*;

const DFWRS_FORWARD_CHAIN: &'static str = "DFWRS_FORWARD";
const DFWRS_INPUT_CHAIN: &'static str = "DFWRS_INPUT";
const DFWRS_POSTROUTING_CHAIN: &'static str = "DFWRS_POSTROUTING";
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

pub struct ProcessDFW<'a> {
    docker: &'a Docker,
    dfw: &'a DFW,
    ipt4: IPTables,
    ipt6: IPTables,
    container_map: Map<String, Container>,
    network_map: Map<String, NetworkDetails>,
    external_network_interface: Option<String>,
}

impl<'a> ProcessDFW<'a> {
    pub fn new(docker: &'a Docker, dfw: &'a DFW) -> Result<ProcessDFW<'a>> {
        let containers = docker.containers().list(&Default::default())?;
        let container_map = get_container_map(&containers)?
            .ok_or_else(|| "no containers found")?;
        let networks = docker.networks().list(&Default::default())?;
        let network_map = get_network_map(&networks)?
            .ok_or_else(|| "no networks found")?;

        let external_network_interface = dfw.defaults
            .as_ref()
            .and_then(|d| d.external_network_interface.clone());

        Ok(ProcessDFW {
               docker: docker,
               dfw: dfw,
               ipt4: iptables::new(false)?,
               ipt6: iptables::new(true)?,
               container_map: container_map,
               network_map: network_map,
               external_network_interface: external_network_interface,
           })
    }

    pub fn process(&self) -> Result<()> {
        create_and_flush_chain("filter", DFWRS_FORWARD_CHAIN, &self.ipt4, &self.ipt6)?;
        create_and_flush_chain("filter", DFWRS_INPUT_CHAIN, &self.ipt4, &self.ipt6)?;
        create_and_flush_chain("nat", DFWRS_PREROUTING_CHAIN, &self.ipt4, &self.ipt6)?;
        create_and_flush_chain("nat", DFWRS_POSTROUTING_CHAIN, &self.ipt4, &self.ipt6)?;

        println!("\n==> process_initialization\n");
        if let Some(ref init) = self.dfw.initialization {
            self.process_initialization(init)?;
        }

        // Setup input and forward chain
        initialize_chain("filter", DFWRS_INPUT_CHAIN, &self.ipt4, &self.ipt6)?;
        self.ipt4
            .append("filter", "INPUT", &format!("-j {}", DFWRS_INPUT_CHAIN))?;
        initialize_chain("filter", DFWRS_FORWARD_CHAIN, &self.ipt4, &self.ipt6)?;
        self.ipt4
            .append("filter", "FORWARD", &format!("-j {}", DFWRS_FORWARD_CHAIN))?;
        // TODO: verify what is needed for ipt6

        // Setup pre- and postrouting
        self.ipt4
            .append("nat",
                    "PREROUTING",
                    &format!("-j {}", DFWRS_PREROUTING_CHAIN))?;
        self.ipt4
            .append("nat",
                    "POSTROUTING",
                    &format!("-j {}", DFWRS_POSTROUTING_CHAIN))?;
        // TODO: verify what is needed for ipt6

        let external_network_interface = self.dfw
            .defaults
            .as_ref()
            .and_then(|d| d.external_network_interface.clone());

        println!("\n\n==> process_container_to_container\n");
        if let Some(ref ctc) = self.dfw.container_to_container {
            self.process_container_to_container(ctc)?;
        }
        println!("\n\n==> process_container_to_wider_world\n");
        if let Some(ref ctww) = self.dfw.container_to_wider_world {
            self.process_container_to_wider_world(ctww)?;
        }
        println!("\n\n==> process_container_to_host\n");
        if let Some(ref cth) = self.dfw.container_to_host {
            self.process_container_to_host(cth)?;
        }
        println!("\n\n==> process_wider_world_to_container\n");
        if let Some(ref wwtc) = self.dfw.wider_world_to_container {
            self.process_wider_world_to_container(wwtc)?;
        }
        println!("\n\n==> process_container_dnat\n");
        if let Some(ref cd) = self.dfw.container_dnat {
            self.process_container_dnat(cd)?;
        }

        if let Some(external_network_interface) = external_network_interface {
            // Add accept rules for Docker bridge
            if let Some(bridge_network) = self.network_map.get("bridge") {
                if let Some(bridge_name) =
                    bridge_network
                        .Options
                        .as_ref()
                        .ok_or("error")?
                        .get("com.docker.network.bridge.name") {
                    println!("bridge_name: {}", bridge_name);
                    let rule_str = Rule::default()
                        .in_interface(bridge_name.to_owned())
                        .out_interface(external_network_interface.to_owned())
                        .jump("ACCEPT".to_owned())
                        .build()?;
                    println!("accept-rule: {}", rule_str);
                    self.ipt4
                        .append("filter", DFWRS_FORWARD_CHAIN, &rule_str)?;
                    // TODO: verify what is needed for ipt6

                    let rule_str = Rule::default()
                        .in_interface(bridge_name.to_owned())
                        .jump("ACCEPT".to_owned())
                        .build()?;
                    self.ipt4
                        .append("filter", DFWRS_INPUT_CHAIN, &rule_str)?;
                    // TODO: verify what is needed for ipt6
                }
            }

            // Configure POSTROUTING
            let rule_str = Rule::default()
                .out_interface(external_network_interface.to_owned())
                .jump("MASQUERADE".to_owned())
                .build()?;
            self.ipt4
                .append("nat", DFWRS_POSTROUTING_CHAIN, &rule_str)?;
            // TODO: verify what is needed for ipt6
        }

        // Set default policy for forward chain (defined by `container_to_container`)
        if let Some(ref ctc) = self.dfw.container_to_container {
            self.ipt4
                .append("filter",
                        DFWRS_FORWARD_CHAIN,
                        &format!("-j {}", ctc.default_policy))?;
            // TODO: verify what is needed for ipt6
        }

        Ok(())
    }

    fn process_initialization(&self, init: &Initialization) -> Result<()> {
        if let Some(ref v4) = init.v4 {
            for (table, rules) in v4.iter() {
                println!("table: {}", table);
                for rule in rules {
                    println!("  RULE: {}", rule);
                    let out = self.ipt4.execute(table, rule)?;
                    println!(" status: {:?}", out.status);
                }
            }
        }

        if let Some(ref v6) = init.v6 {
            for (table, rules) in v6.iter() {
                println!("table: {}", table);
                for rule in rules {
                    println!("  RULE: {}", rule);
                    let out = self.ipt6.execute(table, rule)?;
                    println!(" status: {:?}", out.status);
                }
            }
        }

        Ok(())
    }

    fn process_container_to_container(&self, ctc: &ContainerToContainer) -> Result<()> {
        if ctc.rules.is_some() {
            self.process_ctc_rules(ctc.rules.as_ref().unwrap())?;
        }

        Ok(())
    }

    fn process_ctc_rules(&self, rules: &Vec<ContainerToContainerRule>) -> Result<()> {
        for rule in rules {
            println!("{:#?}", rule);
            let mut ipt_rule = Rule::default();

            let network = match self.network_map.get(&rule.network) {
                Some(network) => network,
                None => continue,
            };
            let bridge_name = get_bridge_name(&network.Id)?;
            ipt_rule
                .in_interface(bridge_name.to_owned())
                .out_interface(bridge_name.to_owned());

            if let Some(ref src_container) = rule.src_container {
                let src_network = match get_network_for_container(&self.docker,
                                                                  &self.container_map,
                                                                  &src_container,
                                                                  &network.Id)? {
                    Some(src_network) => src_network,
                    None => continue,
                };

                let bridge_name = get_bridge_name(&network.Id)?;
                ipt_rule
                    .in_interface(bridge_name.to_owned())
                    .out_interface(bridge_name.to_owned())
                    .source(src_network
                                .IPv4Address
                                .split("/")
                                .next()
                                .unwrap()
                                .to_owned());
            }

            if let Some(ref dst_container) = rule.dst_container {
                let dst_network = match get_network_for_container(&self.docker,
                                                                  &self.container_map,
                                                                  &dst_container,
                                                                  &network.Id)? {
                    Some(dst_network) => dst_network,
                    None => continue,
                };

                let bridge_name = get_bridge_name(&network.Id)?;
                ipt_rule
                    .out_interface(bridge_name.to_owned())
                    .destination(dst_network
                                     .IPv4Address
                                     .split("/")
                                     .next()
                                     .unwrap()
                                     .to_owned());
            }

            // Set jump
            ipt_rule.jump(rule.action.to_owned());

            let rule_str = ipt_rule.build()?;
            println!("{:#?}", rule_str);

            // Apply the rule
            self.ipt4
                .append("filter", DFWRS_FORWARD_CHAIN, &rule_str)?;
            // TODO: verify what is needed for ipt6
        }

        Ok(())
    }

    fn process_container_to_wider_world(&self, ctww: &ContainerToWiderWorld) -> Result<()> {
        // Rules
        if ctww.rules.is_some() {
            self.process_ctww_rules(ctww.rules.as_ref().unwrap())?;
        }

        // Default policy
        if self.external_network_interface.is_some() {
            let external_network_interface = self.external_network_interface.as_ref().unwrap();

            for (_, network) in &self.network_map {
                let bridge_name = get_bridge_name(&network.Id)?;
                let rule = Rule::default()
                    .in_interface(bridge_name)
                    .out_interface(external_network_interface.to_owned())
                    .jump(ctww.default_policy.to_owned())
                    .build()?;

                println!("{:?}", rule);
                self.ipt4.append("filter", DFWRS_FORWARD_CHAIN, &rule)?;
                // TODO: verify what is needed for ipt6
            }
        }

        Ok(())
    }

    fn process_ctww_rules(&self, rules: &Vec<ContainerToWiderWorldRule>) -> Result<()> {
        for rule in rules {
            println!("{:#?}", rule);
            let mut ipt_rule = Rule::default();

            if let Some(ref network) = rule.network {
                if let Some(network) = self.network_map.get(network) {
                    let bridge_name = get_bridge_name(&network.Id)?;
                    ipt_rule.in_interface(bridge_name.to_owned());

                    if let Some(ref src_container) = rule.src_container {
                        if let Some(src_network) =
                            get_network_for_container(&self.docker,
                                                      &self.container_map,
                                                      &src_container,
                                                      &network.Id)? {
                            let bridge_name = get_bridge_name(&network.Id)?;
                            ipt_rule
                                .in_interface(bridge_name.to_owned())
                                .source(src_network
                                            .IPv4Address
                                            .split("/")
                                            .next()
                                            .unwrap()
                                            .to_owned());
                        }
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
            } else if let Some(ref external_network_interface) = self.external_network_interface {
                ipt_rule.out_interface(external_network_interface.to_owned().to_owned());
            }

            let rule_str = ipt_rule.build()?;
            println!("{:#?}", rule_str);

            // Apply the rule
            self.ipt4
                .append("filter", DFWRS_FORWARD_CHAIN, &rule_str)?;
            // TODO: verify what is needed for ipt6
        }

        Ok(())
    }

    fn process_container_to_host(&self, cth: &ContainerToHost) -> Result<()> {
        // Rules
        if cth.rules.is_some() {
            self.process_cth_rules(cth.rules.as_ref().unwrap())?;
        }

        // Default policy
        for (_, network) in &self.network_map {
            let bridge_name = get_bridge_name(&network.Id)?;
            let rule = Rule::default()
                .in_interface(bridge_name)
                .jump(cth.default_policy.to_owned())
                .build()?;

            println!("{:?}", rule);
            self.ipt4.append("filter", DFWRS_INPUT_CHAIN, &rule)?;
            // TODO: verify what is needed for ipt6
        }

        Ok(())
    }

    fn process_cth_rules(&self, rules: &Vec<ContainerToHostRule>) -> Result<()> {
        for rule in rules {
            println!("{:#?}", rule);
            let mut ipt_rule = Rule::default();

            let network = match self.network_map.get(&rule.network) {
                Some(network) => network,
                None => continue,
            };
            let bridge_name = get_bridge_name(&network.Id)?;
            ipt_rule.in_interface(bridge_name.to_owned());

            if let Some(ref src_container) = rule.src_container {
                if let Some(src_network) =
                    get_network_for_container(&self.docker,
                                              &self.container_map,
                                              &src_container,
                                              &network.Id)? {
                    ipt_rule.source(src_network
                                        .IPv4Address
                                        .split("/")
                                        .next()
                                        .unwrap()
                                        .to_owned());
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
            self.ipt4
                .append("filter", DFWRS_INPUT_CHAIN, &rule_str)?;
            // TODO: verify what is needed for ipt6
        }

        Ok(())
    }

    fn process_wider_world_to_container(&self, wwtc: &WiderWorldToContainer) -> Result<()> {
        if wwtc.rules.is_none() {
            return Ok(());
        }
        let rules = wwtc.rules.as_ref().unwrap();

        for rule in rules {
            println!("{:#?}", rule);
            let mut ipt_forward_rule = Rule::default();
            let mut ipt_dnat_rule = Rule::default();

            let network = match self.network_map.get(&rule.network) {
                Some(network) => network,
                None => continue,
            };
            let bridge_name = get_bridge_name(&network.Id)?;
            ipt_forward_rule.out_interface(bridge_name.to_owned());

            if let Some(dst_network) =
                get_network_for_container(&self.docker,
                                          &self.container_map,
                                          &rule.dst_container,
                                          &network.Id)? {
                ipt_forward_rule.destination(dst_network
                                                 .IPv4Address
                                                 .split("/")
                                                 .next()
                                                 .unwrap()
                                                 .to_owned());

                let destination_port = match rule.expose_port.container_port {
                    Some(destination_port) => destination_port.to_string(),
                    None => rule.expose_port.host_port.to_string(),
                };
                ipt_forward_rule.destination_port(destination_port.to_owned());
                ipt_dnat_rule.destination_port(destination_port.to_owned());
                ipt_dnat_rule.filter(format!("--to-destination {}:{}",
                                             dst_network.IPv4Address.split("/").next().unwrap(),
                                             destination_port));
            } else {
                // Network for container has to exist
                continue;
            }

            // Set correct protocol
            ipt_forward_rule.protocol(rule.expose_port.family.to_owned());
            ipt_dnat_rule.protocol(rule.expose_port.family.to_owned());

            ipt_forward_rule.jump("ACCEPT".to_owned());
            ipt_dnat_rule.jump("DNAT".to_owned());

            // Try to build the rule without the out_interface defined to see if any of the other
            // mandatory fields has been populated.
            ipt_forward_rule.build()?; // TODO: maybe add a `verify` method to `Rule`
            ipt_dnat_rule.build()?; // TODO: maybe add a `verify` method to `Rule`

            if let Some(ref external_network_interface) = rule.external_network_interface {
                ipt_forward_rule.in_interface(external_network_interface.to_owned());
                ipt_dnat_rule.in_interface(external_network_interface.to_owned());
            } else if let Some(ref external_network_interface) = self.external_network_interface {
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
            self.ipt4
                .append("filter", DFWRS_FORWARD_CHAIN, &forward_rule_str)?;
            self.ipt4
                .append("nat", DFWRS_PREROUTING_CHAIN, &dnat_rule_str)?;
            // TODO: verify what is needed for ipt6
        }

        Ok(())
    }

    fn process_container_dnat(&self, cd: &ContainerDNAT) -> Result<()> {
        if cd.rules.is_none() {
            return Ok(());
        }
        let rules = cd.rules.as_ref().unwrap();

        for rule in rules {
            println!("{:#?}", rule);
            let mut ipt_rule = Rule::default();

            if let Some(ref network) = rule.src_network {
                if let Some(network) = self.network_map.get(network) {
                    let bridge_name = get_bridge_name(&network.Id)?;
                    ipt_rule.in_interface(bridge_name.to_owned());

                    if let Some(ref src_container) = rule.src_container {
                        if let Some(src_network) =
                            get_network_for_container(&self.docker,
                                                      &self.container_map,
                                                      &src_container,
                                                      &network.Id)? {
                            let bridge_name = get_bridge_name(&network.Id)?;
                            ipt_rule
                                .in_interface(bridge_name.to_owned())
                                .source(src_network
                                            .IPv4Address
                                            .split("/")
                                            .next()
                                            .unwrap()
                                            .to_owned());
                        }
                    }
                }
            }

            let network = match self.network_map.get(&rule.dst_network) {
                Some(network) => network,
                None => continue,
            };
            let dst_network = match get_network_for_container(&self.docker,
                                                              &self.container_map,
                                                              &rule.dst_container,
                                                              &network.Id)? {
                Some(dst_network) => dst_network,
                None => continue,
            };
            let destination_port = match rule.expose_port.container_port {
                Some(destination_port) => destination_port.to_string(),
                None => rule.expose_port.host_port.to_string(),
            };
            ipt_rule.destination_port(destination_port.to_owned());
            ipt_rule.filter(format!("--to-destination {}:{}",
                                    dst_network.IPv4Address.split("/").next().unwrap(),
                                    destination_port));

            ipt_rule.jump("DNAT".to_owned());

            // Try to build the rule without the out_interface defined to see if any of the other
            // mandatory fields has been populated.
            ipt_rule.build()?; // TODO: maybe add a `verify` method to `Rule`

            if ipt_rule.out_interface.is_none() {
                if let Some(ref external_network_interface) = self.external_network_interface {
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
            self.ipt4
                .append("nat", DFWRS_PREROUTING_CHAIN, &rule_str)?;
            // TODO: verify what is needed for ipt6
        }

        Ok(())
    }
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

fn get_network_for_container(docker: &Docker,
                             container_map: &Map<String, Container>,
                             container_name: &str,
                             network_id: &str)
                             -> Result<Option<NetworkContainerDetails>> {
    Ok(match container_map.get(container_name) {
           Some(container) => {
               match docker
                         .networks()
                         .get(network_id)
                         .inspect()?
                         .Containers
                         .get(&container.Id) {
                   Some(network) => Some(network.clone()),
                   None => None,
               }
           }
           None => None,
       })
}

fn get_container_map(containers: &Vec<Container>) -> Result<Option<Map<String, Container>>> {
    let mut container_map: Map<String, Container> = Map::new();
    for container in containers {
        for name in &container.Names {
            container_map.insert(name.clone().trim_left_matches("/").to_owned(),
                                 container.clone());
        }
    }

    if container_map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(container_map))
    }
}

fn get_network_map(networks: &Vec<NetworkDetails>) -> Result<Option<Map<String, NetworkDetails>>> {
    let mut network_map: Map<String, NetworkDetails> = Map::new();
    for network in networks {
        network_map.insert(network.Name.clone(), network.clone());
    }

    if network_map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(network_map))
    }
}
