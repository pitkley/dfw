var searchIndex = JSON.parse('{\
"dfw":{"doc":"DFW - Docker Firewall Framework in RustFor detailed…","i":[[0,"errors","dfw","Errors, using `failure`.",null,null],[4,"DFWError","dfw::errors","",null,null],[13,"NFTablesError","","",0,null],[12,"stdout","dfw::errors::DFWError","",1,null],[12,"stderr","","",1,null],[13,"TraitMethodUnimplemented","dfw::errors","",0,null],[12,"method","dfw::errors::DFWError","",2,null],[6,"Result","dfw::errors","",null,null],[0,"iptables","dfw","This module implements the iptables backend for DFW.",null,null],[3,"Iptables","dfw::iptables","Marker struct to implement iptables as a firewall backend.",null,null],[4,"IptablesRule","","Rule representation for iptables firewall backend.",null,null],[13,"V4","","IPv4",3,null],[13,"V6","","IPv6",3,null],[4,"IptablesRuleDiscriminants","","Auto-generated discriminant enum variants",null,null],[13,"V4","","IPv4",4,null],[13,"V6","","IPv6",4,null],[4,"PolicyOrRule","","Policy or rule representation for iptables firewall backend.",null,null],[13,"Policy","","Rule specifying a chain policy.",5,null],[12,"table","dfw::iptables::PolicyOrRule","Associated iptables table.",6,null],[12,"chain","","Associated iptables chain.",6,null],[12,"policy","","Policy to set.",6,null],[13,"Rule","dfw::iptables","Actual filter rule that will be added to a chain.",5,null],[12,"table","dfw::iptables::PolicyOrRule","Associated iptables table.",7,null],[12,"chain","","Associated iptables chain.",7,null],[12,"value","","The rule itself in valid iptables syntax.",7,null],[0,"types","dfw::iptables","The types in this module make up the structure of the…",null,null],[3,"Defaults","dfw::iptables::types","The defaults/configuration for the iptables backend.",null,null],[12,"initialization","","The optional initialization section.",8,null],[3,"Initialization","","The initialization section allows you to add custom rules…",null,null],[12,"v4","","Initialization rules for iptables (IPv4). Expects a map…",9,null],[12,"v6","","Initialization rules for ip6tables (IPv6). Expects a map…",9,null],[11,"get_rules","dfw::iptables","Retrieve the current text that would be passed to…",10,[[["iptablesrulediscriminants",4],["iptablesrule",4],["vec",3]],[["vec",3],["string",3]]]],[0,"nftables","dfw","This module implements the nftables backend for DFW.",null,null],[3,"Nftables","dfw::nftables","Marker struct to implement nftables as a firewall backend.",null,null],[4,"Family","","Representation of nftables table-families.",null,null],[13,"Ip","","IPv4 table family",11,null],[13,"Ip6","","IPv6 table family",11,null],[13,"Inet","","Dualstack IPv4/IPv6 table family",11,null],[13,"Arp","","ARP table family",11,null],[13,"Bridge","","Bridge table family",11,null],[13,"Netdev","","Netdev table family",11,null],[4,"Type","","Representation of nftables chain-types.",null,null],[13,"Filter","","Is used to filter packets.",12,null],[13,"Route","","Is used to reroute packets if any relevant IP header field…",12,null],[13,"Nat","","Is used to perform Networking Address Translation (NAT).",12,null],[4,"Hook","","Representation of nftables chain hooks.",null,null],[13,"Ingress","","Ingress allows traffic-filtering before pre-routing, after…",13,null],[13,"Prerouting","","Prerouting allows traffic-filtering before the packets…",13,null],[13,"Input","","Input allows traffic-filtering for packets that have been…",13,null],[13,"Forward","","Forward allows traffic-filtering for packets that were not…",13,null],[13,"Output","","Output allows traffic-filtering for packets leaving the…",13,null],[13,"Postrouting","","Postrouting allows traffic-filtering for already routed…",13,null],[0,"types","","The types in this module make up the structure of the…",null,null],[3,"Defaults","dfw::nftables::types","The defaults/configuration for the nftables backend.",null,null],[12,"custom_tables","","Specify the names of custom nft-tables that should be…",14,null],[12,"initialization","","The optional initialization section.",14,null],[3,"Table","","Reference to an nftables table, specifically to the input-…",null,null],[12,"name","","Name of the custom table.",15,null],[12,"chains","","Names of the input and forward chains defined within the…",15,null],[3,"Initialization","","The initialization section allows you to execute any…",null,null],[12,"rules","","Initialization rules for nftables",16,null],[0,"process","dfw","This module holds the types related to configuration…",null,null],[3,"ProcessContext","dfw::process","Enclosing struct to manage rule processing.",null,null],[3,"ProcessingOptions","","Options to configure the processing procedure.",null,null],[12,"container_filter","","Option to filter the containers to be processed, see…",17,null],[4,"ContainerFilter","","Option to filter the containers to be processed",null,null],[13,"All","","Process all containers, i.e. don\'t filter.",18,null],[13,"Running","","Only process running containers.",18,null],[8,"Process","","This trait allows a type to define its own processing…",null,null],[10,"process","","Process the current type within the given…",19,[[["processcontext",3]],[["option",4],["result",6]]]],[11,"new","","Create a new instance of `ProcessDFW` for rule processing.",20,[[["logger",3],["dfw",3],["docker",3],["processingoptions",3]],[["result",6],["processcontext",3]]]],[11,"process","","Start the processing using the configuration given at…",20,[[],["result",6]]],[0,"types","dfw","The types in this module make up the structure of the…",null,null],[3,"DFW","dfw::types","`DFW` is the parent type defining the complete…",null,null],[12,"global_defaults","","The `defaults` configuration section.",21,null],[12,"backend_defaults","","The `backend_defaults` configuration section",21,null],[12,"initialization","","This field is DEPRECATED!Provide the custom tables in the…",21,null],[12,"container_to_container","","The `container_to_container` configuration section",21,null],[12,"container_to_wider_world","","The `container_to_wider_world` configuration section",21,null],[12,"container_to_host","","The `container_to_host` configuration section",21,null],[12,"wider_world_to_container","","The `wider_world_to_container` configuration section",21,null],[12,"container_dnat","","The `container_dnat` configuration section",21,null],[3,"GlobalDefaults","","The default configuration section, used by DFW for rule…",null,null],[12,"external_network_interfaces","","This defines the external network interfaces of the host…",22,null],[12,"default_docker_bridge_to_host_policy","","This defines whether the default Docker bridge (usually…",22,null],[12,"custom_tables","","This field is DEPRECATED!Provide the custom tables in the…",22,null],[3,"ContainerToContainer","","The container-to-container section, defining how…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",23,null],[12,"rules","","An optional list of rules, see `ContainerToContainerRule`.",23,null],[3,"ContainerToContainerRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Common network between the source container and the…",24,null],[12,"src_container","","Source container to apply the rule to.",24,null],[12,"dst_container","","Destination container to apply the rule to.",24,null],[12,"matches","","Additional match-string, which will be added to the…",24,null],[12,"verdict","","Verdict for rule (accept, drop or reject).",24,null],[3,"ContainerToWiderWorld","","The container-to-wider-world section, defining how…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",25,null],[12,"rules","","An optional list of rules, see `ContainerToWiderWorldRule`.",25,null],[3,"ContainerToWiderWorldRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Network of the source container to apply the rule to.",26,null],[12,"src_container","","Source container to apply the rule to.",26,null],[12,"matches","","Additional match-string, which will be added to the…",26,null],[12,"verdict","","Verdict for rule (accept, drop or reject).",26,null],[12,"external_network_interface","","Specific external network interface to target.",26,null],[3,"ContainerToHost","","The container-to-host section, defining how containers can…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",27,null],[12,"rules","","An optional list of rules, see `ContainerToHostRule`.",27,null],[3,"ContainerToHostRule","","Definition for a rule to be used in the container-to-host…",null,null],[12,"network","","Network of the source container to apply the rule to.",28,null],[12,"src_container","","Source container to apply the rule to.",28,null],[12,"matches","","Additional match-string, which will be added to the…",28,null],[12,"verdict","","Verdict for rule (accept, drop or reject).",28,null],[3,"WiderWorldToContainer","","The wider-world-to-container section, defining how…",null,null],[12,"rules","","An optional list of rules, see `WiderWorldToContainerRule`.",29,null],[3,"WiderWorldToContainerRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Network of the destination container to apply the rule to.",30,null],[12,"dst_container","","Destination container to apply the rule to.",30,null],[12,"expose_port","","Ports to apply the rule to.",30,null],[12,"external_network_interface","","Specific external network interface to target.",30,null],[12,"expose_via_ipv6","","Configure if the container should be exposed via IPv6,…",30,null],[12,"source_cidr_v4","","Source CIDRs (IPv4) to which incoming traffic should be…",30,null],[12,"source_cidr_v6","","Source CIDRs (IPv6) to which incoming traffic should be…",30,null],[3,"ExposePort","","Struct to hold a port definition to expose on the…",null,null],[12,"host_port","","Port the `container_port` should be exposed to on the host.",31,null],[12,"container_port","","Port the `host_port` should map to into the container.",31,null],[12,"family","","Family of the exposed port.",31,null],[3,"ExposePortBuilder","","Builder for `ExposePort`.",null,null],[12,"host_port","","Port the `container_port` should be exposed to on the host.",32,null],[12,"container_port","","Port the `host_port` should map to into the container.",32,null],[12,"family","","Family of the exposed port.",32,null],[3,"ContainerDNAT","","The container-DNAT section, defining how containers can…",null,null],[12,"rules","","An optional list of rules, see `ContainerDNATRule`.",33,null],[3,"ContainerDNATRule","","Definition for a rule to be used in the container-DNAT…",null,null],[12,"src_network","","Network of the source container to apply the rule to.",34,null],[12,"src_container","","Source container to apply the rule to.",34,null],[12,"dst_network","","Network of the destination container to apply the rule to.",34,null],[12,"dst_container","","Destination container to apply the rule to.",34,null],[12,"expose_port","","Ports to apply the rule to.",34,null],[4,"ChainPolicy","","Representation of chain policies.",null,null],[13,"Accept","","The accept verdict means that the packet will keep…",35,null],[13,"Drop","","The drop verdict means that the packet is discarded if the…",35,null],[4,"RuleVerdict","","Representation of rule policies.",null,null],[13,"Accept","","The accept verdict means that the packet will keep…",36,null],[13,"Drop","","The drop verdict means that the packet is discarded if the…",36,null],[13,"Reject","","The reject verdict means that the packet is responded to…",36,null],[11,"host_port","","Port the `container_port` should be exposed to on the host.",32,[[]]],[11,"container_port","","Port the `host_port` should map to into the container.",32,[[["option",4]]]],[11,"family","","Family of the exposed port.",32,[[["string",3]]]],[11,"build","","Builds a new `ExposePort`.",32,[[],[["string",3],["result",4],["exposeport",3]]]],[0,"util","dfw","Utilities module",null,null],[5,"load_file","dfw::util","Load single TOML-file from path and deserialize it into…",null,[[],["result",6]]],[5,"load_path","","Load all TOML-files from a path, concatenate their…",null,[[],["result",6]]],[8,"FutureExt","","An extension trait for `Future` allowing synchronized…",null,null],[11,"sync","","Execute future synchronously, blocking until a result can…",37,[[],["result",4]]],[8,"FirewallBackend","dfw","This trait is used to distinguish between different…",null,null],[16,"Rule","","Associated type identifying the rule-type returned.",38,null],[16,"Defaults","","Associated type representing the firewall backend…",38,null],[10,"apply","","Apply the processed rules.",38,[[["processcontext",3],["vec",3]],["result",6]]],[11,"from","dfw::errors","",0,[[]]],[11,"into","","",0,[[]]],[11,"to_string","","",0,[[],["string",3]]],[11,"borrow","","",0,[[]]],[11,"borrow_mut","","",0,[[]]],[11,"try_from","","",0,[[],["result",4]]],[11,"try_into","","",0,[[],["result",4]]],[11,"type_id","","",0,[[],["typeid",3]]],[11,"as_fail","","",0,[[],["fail",8]]],[11,"vzip","","",0,[[]]],[11,"from","dfw::iptables","",10,[[]]],[11,"into","","",10,[[]]],[11,"borrow","","",10,[[]]],[11,"borrow_mut","","",10,[[]]],[11,"try_from","","",10,[[],["result",4]]],[11,"try_into","","",10,[[],["result",4]]],[11,"type_id","","",10,[[],["typeid",3]]],[11,"vzip","","",10,[[]]],[11,"from","","",3,[[]]],[11,"into","","",3,[[]]],[11,"to_owned","","",3,[[]]],[11,"clone_into","","",3,[[]]],[11,"borrow","","",3,[[]]],[11,"borrow_mut","","",3,[[]]],[11,"try_from","","",3,[[],["result",4]]],[11,"try_into","","",3,[[],["result",4]]],[11,"type_id","","",3,[[],["typeid",3]]],[11,"vzip","","",3,[[]]],[11,"from","","",4,[[]]],[11,"into","","",4,[[]]],[11,"to_owned","","",4,[[]]],[11,"clone_into","","",4,[[]]],[11,"borrow","","",4,[[]]],[11,"borrow_mut","","",4,[[]]],[11,"try_from","","",4,[[],["result",4]]],[11,"try_into","","",4,[[],["result",4]]],[11,"type_id","","",4,[[],["typeid",3]]],[11,"equivalent","","",4,[[]]],[11,"vzip","","",4,[[]]],[11,"from","","",5,[[]]],[11,"into","","",5,[[]]],[11,"to_owned","","",5,[[]]],[11,"clone_into","","",5,[[]]],[11,"borrow","","",5,[[]]],[11,"borrow_mut","","",5,[[]]],[11,"try_from","","",5,[[],["result",4]]],[11,"try_into","","",5,[[],["result",4]]],[11,"type_id","","",5,[[],["typeid",3]]],[11,"vzip","","",5,[[]]],[11,"from","dfw::iptables::types","",8,[[]]],[11,"into","","",8,[[]]],[11,"to_owned","","",8,[[]]],[11,"clone_into","","",8,[[]]],[11,"borrow","","",8,[[]]],[11,"borrow_mut","","",8,[[]]],[11,"try_from","","",8,[[],["result",4]]],[11,"try_into","","",8,[[],["result",4]]],[11,"type_id","","",8,[[],["typeid",3]]],[11,"equivalent","","",8,[[]]],[11,"vzip","","",8,[[]]],[11,"from","","",9,[[]]],[11,"into","","",9,[[]]],[11,"to_owned","","",9,[[]]],[11,"clone_into","","",9,[[]]],[11,"borrow","","",9,[[]]],[11,"borrow_mut","","",9,[[]]],[11,"try_from","","",9,[[],["result",4]]],[11,"try_into","","",9,[[],["result",4]]],[11,"type_id","","",9,[[],["typeid",3]]],[11,"equivalent","","",9,[[]]],[11,"vzip","","",9,[[]]],[11,"from","dfw::nftables","",39,[[]]],[11,"into","","",39,[[]]],[11,"borrow","","",39,[[]]],[11,"borrow_mut","","",39,[[]]],[11,"try_from","","",39,[[],["result",4]]],[11,"try_into","","",39,[[],["result",4]]],[11,"type_id","","",39,[[],["typeid",3]]],[11,"vzip","","",39,[[]]],[11,"from","","",11,[[]]],[11,"into","","",11,[[]]],[11,"to_owned","","",11,[[]]],[11,"clone_into","","",11,[[]]],[11,"to_string","","",11,[[],["string",3]]],[11,"borrow","","",11,[[]]],[11,"borrow_mut","","",11,[[]]],[11,"try_from","","",11,[[],["result",4]]],[11,"try_into","","",11,[[],["result",4]]],[11,"type_id","","",11,[[],["typeid",3]]],[11,"vzip","","",11,[[]]],[11,"from","","",12,[[]]],[11,"into","","",12,[[]]],[11,"to_owned","","",12,[[]]],[11,"clone_into","","",12,[[]]],[11,"to_string","","",12,[[],["string",3]]],[11,"borrow","","",12,[[]]],[11,"borrow_mut","","",12,[[]]],[11,"try_from","","",12,[[],["result",4]]],[11,"try_into","","",12,[[],["result",4]]],[11,"type_id","","",12,[[],["typeid",3]]],[11,"vzip","","",12,[[]]],[11,"from","","",13,[[]]],[11,"into","","",13,[[]]],[11,"to_owned","","",13,[[]]],[11,"clone_into","","",13,[[]]],[11,"to_string","","",13,[[],["string",3]]],[11,"borrow","","",13,[[]]],[11,"borrow_mut","","",13,[[]]],[11,"try_from","","",13,[[],["result",4]]],[11,"try_into","","",13,[[],["result",4]]],[11,"type_id","","",13,[[],["typeid",3]]],[11,"vzip","","",13,[[]]],[11,"from","dfw::nftables::types","",14,[[]]],[11,"into","","",14,[[]]],[11,"to_owned","","",14,[[]]],[11,"clone_into","","",14,[[]]],[11,"borrow","","",14,[[]]],[11,"borrow_mut","","",14,[[]]],[11,"try_from","","",14,[[],["result",4]]],[11,"try_into","","",14,[[],["result",4]]],[11,"type_id","","",14,[[],["typeid",3]]],[11,"equivalent","","",14,[[]]],[11,"vzip","","",14,[[]]],[11,"from","","",15,[[]]],[11,"into","","",15,[[]]],[11,"to_owned","","",15,[[]]],[11,"clone_into","","",15,[[]]],[11,"borrow","","",15,[[]]],[11,"borrow_mut","","",15,[[]]],[11,"try_from","","",15,[[],["result",4]]],[11,"try_into","","",15,[[],["result",4]]],[11,"type_id","","",15,[[],["typeid",3]]],[11,"equivalent","","",15,[[]]],[11,"vzip","","",15,[[]]],[11,"from","","",16,[[]]],[11,"into","","",16,[[]]],[11,"to_owned","","",16,[[]]],[11,"clone_into","","",16,[[]]],[11,"borrow","","",16,[[]]],[11,"borrow_mut","","",16,[[]]],[11,"try_from","","",16,[[],["result",4]]],[11,"try_into","","",16,[[],["result",4]]],[11,"type_id","","",16,[[],["typeid",3]]],[11,"equivalent","","",16,[[]]],[11,"vzip","","",16,[[]]],[11,"from","dfw::process","",20,[[]]],[11,"into","","",20,[[]]],[11,"borrow","","",20,[[]]],[11,"borrow_mut","","",20,[[]]],[11,"try_from","","",20,[[],["result",4]]],[11,"try_into","","",20,[[],["result",4]]],[11,"type_id","","",20,[[],["typeid",3]]],[11,"vzip","","",20,[[]]],[11,"from","","",17,[[]]],[11,"into","","",17,[[]]],[11,"to_owned","","",17,[[]]],[11,"clone_into","","",17,[[]]],[11,"borrow","","",17,[[]]],[11,"borrow_mut","","",17,[[]]],[11,"try_from","","",17,[[],["result",4]]],[11,"try_into","","",17,[[],["result",4]]],[11,"type_id","","",17,[[],["typeid",3]]],[11,"equivalent","","",17,[[]]],[11,"vzip","","",17,[[]]],[11,"from","","",18,[[]]],[11,"into","","",18,[[]]],[11,"to_owned","","",18,[[]]],[11,"clone_into","","",18,[[]]],[11,"borrow","","",18,[[]]],[11,"borrow_mut","","",18,[[]]],[11,"try_from","","",18,[[],["result",4]]],[11,"try_into","","",18,[[],["result",4]]],[11,"type_id","","",18,[[],["typeid",3]]],[11,"equivalent","","",18,[[]]],[11,"vzip","","",18,[[]]],[11,"from","dfw::types","",21,[[]]],[11,"into","","",21,[[]]],[11,"to_owned","","",21,[[]]],[11,"clone_into","","",21,[[]]],[11,"borrow","","",21,[[]]],[11,"borrow_mut","","",21,[[]]],[11,"try_from","","",21,[[],["result",4]]],[11,"try_into","","",21,[[],["result",4]]],[11,"type_id","","",21,[[],["typeid",3]]],[11,"equivalent","","",21,[[]]],[11,"vzip","","",21,[[]]],[11,"from","","",22,[[]]],[11,"into","","",22,[[]]],[11,"to_owned","","",22,[[]]],[11,"clone_into","","",22,[[]]],[11,"borrow","","",22,[[]]],[11,"borrow_mut","","",22,[[]]],[11,"try_from","","",22,[[],["result",4]]],[11,"try_into","","",22,[[],["result",4]]],[11,"type_id","","",22,[[],["typeid",3]]],[11,"equivalent","","",22,[[]]],[11,"vzip","","",22,[[]]],[11,"from","","",23,[[]]],[11,"into","","",23,[[]]],[11,"to_owned","","",23,[[]]],[11,"clone_into","","",23,[[]]],[11,"borrow","","",23,[[]]],[11,"borrow_mut","","",23,[[]]],[11,"try_from","","",23,[[],["result",4]]],[11,"try_into","","",23,[[],["result",4]]],[11,"type_id","","",23,[[],["typeid",3]]],[11,"equivalent","","",23,[[]]],[11,"vzip","","",23,[[]]],[11,"from","","",24,[[]]],[11,"into","","",24,[[]]],[11,"to_owned","","",24,[[]]],[11,"clone_into","","",24,[[]]],[11,"borrow","","",24,[[]]],[11,"borrow_mut","","",24,[[]]],[11,"try_from","","",24,[[],["result",4]]],[11,"try_into","","",24,[[],["result",4]]],[11,"type_id","","",24,[[],["typeid",3]]],[11,"equivalent","","",24,[[]]],[11,"vzip","","",24,[[]]],[11,"from","","",25,[[]]],[11,"into","","",25,[[]]],[11,"to_owned","","",25,[[]]],[11,"clone_into","","",25,[[]]],[11,"borrow","","",25,[[]]],[11,"borrow_mut","","",25,[[]]],[11,"try_from","","",25,[[],["result",4]]],[11,"try_into","","",25,[[],["result",4]]],[11,"type_id","","",25,[[],["typeid",3]]],[11,"equivalent","","",25,[[]]],[11,"vzip","","",25,[[]]],[11,"from","","",26,[[]]],[11,"into","","",26,[[]]],[11,"to_owned","","",26,[[]]],[11,"clone_into","","",26,[[]]],[11,"borrow","","",26,[[]]],[11,"borrow_mut","","",26,[[]]],[11,"try_from","","",26,[[],["result",4]]],[11,"try_into","","",26,[[],["result",4]]],[11,"type_id","","",26,[[],["typeid",3]]],[11,"equivalent","","",26,[[]]],[11,"vzip","","",26,[[]]],[11,"from","","",27,[[]]],[11,"into","","",27,[[]]],[11,"to_owned","","",27,[[]]],[11,"clone_into","","",27,[[]]],[11,"borrow","","",27,[[]]],[11,"borrow_mut","","",27,[[]]],[11,"try_from","","",27,[[],["result",4]]],[11,"try_into","","",27,[[],["result",4]]],[11,"type_id","","",27,[[],["typeid",3]]],[11,"equivalent","","",27,[[]]],[11,"vzip","","",27,[[]]],[11,"from","","",28,[[]]],[11,"into","","",28,[[]]],[11,"to_owned","","",28,[[]]],[11,"clone_into","","",28,[[]]],[11,"borrow","","",28,[[]]],[11,"borrow_mut","","",28,[[]]],[11,"try_from","","",28,[[],["result",4]]],[11,"try_into","","",28,[[],["result",4]]],[11,"type_id","","",28,[[],["typeid",3]]],[11,"equivalent","","",28,[[]]],[11,"vzip","","",28,[[]]],[11,"from","","",29,[[]]],[11,"into","","",29,[[]]],[11,"to_owned","","",29,[[]]],[11,"clone_into","","",29,[[]]],[11,"borrow","","",29,[[]]],[11,"borrow_mut","","",29,[[]]],[11,"try_from","","",29,[[],["result",4]]],[11,"try_into","","",29,[[],["result",4]]],[11,"type_id","","",29,[[],["typeid",3]]],[11,"equivalent","","",29,[[]]],[11,"vzip","","",29,[[]]],[11,"from","","",30,[[]]],[11,"into","","",30,[[]]],[11,"to_owned","","",30,[[]]],[11,"clone_into","","",30,[[]]],[11,"borrow","","",30,[[]]],[11,"borrow_mut","","",30,[[]]],[11,"try_from","","",30,[[],["result",4]]],[11,"try_into","","",30,[[],["result",4]]],[11,"type_id","","",30,[[],["typeid",3]]],[11,"equivalent","","",30,[[]]],[11,"vzip","","",30,[[]]],[11,"from","","",31,[[]]],[11,"into","","",31,[[]]],[11,"to_owned","","",31,[[]]],[11,"clone_into","","",31,[[]]],[11,"borrow","","",31,[[]]],[11,"borrow_mut","","",31,[[]]],[11,"try_from","","",31,[[],["result",4]]],[11,"try_into","","",31,[[],["result",4]]],[11,"type_id","","",31,[[],["typeid",3]]],[11,"equivalent","","",31,[[]]],[11,"vzip","","",31,[[]]],[11,"from","","",32,[[]]],[11,"into","","",32,[[]]],[11,"to_owned","","",32,[[]]],[11,"clone_into","","",32,[[]]],[11,"borrow","","",32,[[]]],[11,"borrow_mut","","",32,[[]]],[11,"try_from","","",32,[[],["result",4]]],[11,"try_into","","",32,[[],["result",4]]],[11,"type_id","","",32,[[],["typeid",3]]],[11,"vzip","","",32,[[]]],[11,"from","","",33,[[]]],[11,"into","","",33,[[]]],[11,"to_owned","","",33,[[]]],[11,"clone_into","","",33,[[]]],[11,"borrow","","",33,[[]]],[11,"borrow_mut","","",33,[[]]],[11,"try_from","","",33,[[],["result",4]]],[11,"try_into","","",33,[[],["result",4]]],[11,"type_id","","",33,[[],["typeid",3]]],[11,"equivalent","","",33,[[]]],[11,"vzip","","",33,[[]]],[11,"from","","",34,[[]]],[11,"into","","",34,[[]]],[11,"to_owned","","",34,[[]]],[11,"clone_into","","",34,[[]]],[11,"borrow","","",34,[[]]],[11,"borrow_mut","","",34,[[]]],[11,"try_from","","",34,[[],["result",4]]],[11,"try_into","","",34,[[],["result",4]]],[11,"type_id","","",34,[[],["typeid",3]]],[11,"equivalent","","",34,[[]]],[11,"vzip","","",34,[[]]],[11,"from","","",35,[[]]],[11,"into","","",35,[[]]],[11,"to_owned","","",35,[[]]],[11,"clone_into","","",35,[[]]],[11,"to_string","","",35,[[],["string",3]]],[11,"borrow","","",35,[[]]],[11,"borrow_mut","","",35,[[]]],[11,"try_from","","",35,[[],["result",4]]],[11,"try_into","","",35,[[],["result",4]]],[11,"type_id","","",35,[[],["typeid",3]]],[11,"equivalent","","",35,[[]]],[11,"vzip","","",35,[[]]],[11,"from","","",36,[[]]],[11,"into","","",36,[[]]],[11,"to_owned","","",36,[[]]],[11,"clone_into","","",36,[[]]],[11,"to_string","","",36,[[],["string",3]]],[11,"borrow","","",36,[[]]],[11,"borrow_mut","","",36,[[]]],[11,"try_from","","",36,[[],["result",4]]],[11,"try_into","","",36,[[],["result",4]]],[11,"type_id","","",36,[[],["typeid",3]]],[11,"equivalent","","",36,[[]]],[11,"vzip","","",36,[[]]],[11,"process","","",21,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",22,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",23,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",24,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",25,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",26,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",27,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",28,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",29,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",30,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",33,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",34,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",21,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",22,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",23,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",24,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",25,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",26,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",27,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",28,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",29,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",30,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",33,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"process","","",34,[[["processcontext",3]],[["result",6],["option",4]]]],[11,"apply","dfw::iptables","",10,[[["processcontext",3],["vec",3]],["result",6]]],[11,"apply","dfw::nftables","",39,[[["vec",3],["processcontext",3]],["result",6]]],[11,"from","dfw::iptables","",4,[[["iptablesrule",4]],["iptablesrulediscriminants",4]]],[11,"from","","",4,[[["iptablesrule",4]],["iptablesrulediscriminants",4]]],[11,"clone","dfw::iptables::types","",8,[[],["defaults",3]]],[11,"clone","","",9,[[],["initialization",3]]],[11,"clone","dfw::iptables","",3,[[],["iptablesrule",4]]],[11,"clone","","",4,[[],["iptablesrulediscriminants",4]]],[11,"clone","","",5,[[],["policyorrule",4]]],[11,"clone","dfw::nftables::types","",14,[[],["defaults",3]]],[11,"clone","","",15,[[],["table",3]]],[11,"clone","","",16,[[],["initialization",3]]],[11,"clone","dfw::nftables","",11,[[],["family",4]]],[11,"clone","","",12,[[],["type",4]]],[11,"clone","","",13,[[],["hook",4]]],[11,"clone","dfw::process","",18,[[],["containerfilter",4]]],[11,"clone","","",17,[[],["processingoptions",3]]],[11,"clone","dfw::types","",21,[[],["dfw",3]]],[11,"clone","","",22,[[],["globaldefaults",3]]],[11,"clone","","",23,[[],["containertocontainer",3]]],[11,"clone","","",24,[[],["containertocontainerrule",3]]],[11,"clone","","",25,[[],["containertowiderworld",3]]],[11,"clone","","",26,[[],["containertowiderworldrule",3]]],[11,"clone","","",27,[[],["containertohost",3]]],[11,"clone","","",28,[[],["containertohostrule",3]]],[11,"clone","","",29,[[],["widerworldtocontainer",3]]],[11,"clone","","",30,[[],["widerworldtocontainerrule",3]]],[11,"clone","","",31,[[],["exposeport",3]]],[11,"clone","","",32,[[],["exposeportbuilder",3]]],[11,"clone","","",33,[[],["containerdnat",3]]],[11,"clone","","",34,[[],["containerdnatrule",3]]],[11,"clone","","",35,[[],["chainpolicy",4]]],[11,"clone","","",36,[[],["ruleverdict",4]]],[11,"default","dfw::nftables::types","",14,[[],["defaults",3]]],[11,"default","","",15,[[],["table",3]]],[11,"default","","",16,[[],["initialization",3]]],[11,"default","dfw::process","",17,[[]]],[11,"default","dfw::types","",22,[[],["globaldefaults",3]]],[11,"default","","",31,[[],["exposeport",3]]],[11,"default","","",32,[[],["exposeportbuilder",3]]],[11,"default","","",35,[[],["chainpolicy",4]]],[11,"default","","",36,[[],["ruleverdict",4]]],[11,"eq","dfw::iptables::types","",8,[[["defaults",3]]]],[11,"ne","","",8,[[["defaults",3]]]],[11,"eq","","",9,[[["initialization",3]]]],[11,"ne","","",9,[[["initialization",3]]]],[11,"eq","dfw::iptables","",4,[[["iptablesrulediscriminants",4]]]],[11,"eq","dfw::nftables::types","",14,[[["defaults",3]]]],[11,"ne","","",14,[[["defaults",3]]]],[11,"eq","","",15,[[["table",3]]]],[11,"ne","","",15,[[["table",3]]]],[11,"eq","","",16,[[["initialization",3]]]],[11,"ne","","",16,[[["initialization",3]]]],[11,"eq","dfw::process","",18,[[["containerfilter",4]]]],[11,"eq","","",17,[[["processingoptions",3]]]],[11,"ne","","",17,[[["processingoptions",3]]]],[11,"eq","dfw::types","",21,[[["dfw",3]]]],[11,"ne","","",21,[[["dfw",3]]]],[11,"eq","","",22,[[["globaldefaults",3]]]],[11,"ne","","",22,[[["globaldefaults",3]]]],[11,"eq","","",23,[[["containertocontainer",3]]]],[11,"ne","","",23,[[["containertocontainer",3]]]],[11,"eq","","",24,[[["containertocontainerrule",3]]]],[11,"ne","","",24,[[["containertocontainerrule",3]]]],[11,"eq","","",25,[[["containertowiderworld",3]]]],[11,"ne","","",25,[[["containertowiderworld",3]]]],[11,"eq","","",26,[[["containertowiderworldrule",3]]]],[11,"ne","","",26,[[["containertowiderworldrule",3]]]],[11,"eq","","",27,[[["containertohost",3]]]],[11,"ne","","",27,[[["containertohost",3]]]],[11,"eq","","",28,[[["containertohostrule",3]]]],[11,"ne","","",28,[[["containertohostrule",3]]]],[11,"eq","","",29,[[["widerworldtocontainer",3]]]],[11,"ne","","",29,[[["widerworldtocontainer",3]]]],[11,"eq","","",30,[[["widerworldtocontainerrule",3]]]],[11,"ne","","",30,[[["widerworldtocontainerrule",3]]]],[11,"eq","","",31,[[["exposeport",3]]]],[11,"ne","","",31,[[["exposeport",3]]]],[11,"eq","","",33,[[["containerdnat",3]]]],[11,"ne","","",33,[[["containerdnat",3]]]],[11,"eq","","",34,[[["containerdnatrule",3]]]],[11,"ne","","",34,[[["containerdnatrule",3]]]],[11,"eq","","",35,[[["chainpolicy",4]]]],[11,"eq","","",36,[[["ruleverdict",4]]]],[11,"fmt","dfw::errors","",0,[[["formatter",3]],["result",6]]],[11,"fmt","dfw::iptables::types","",8,[[["formatter",3]],["result",6]]],[11,"fmt","","",9,[[["formatter",3]],["result",6]]],[11,"fmt","dfw::iptables","",10,[[["formatter",3]],["result",6]]],[11,"fmt","","",3,[[["formatter",3]],["result",6]]],[11,"fmt","","",4,[[["formatter",3]],["result",6]]],[11,"fmt","","",5,[[["formatter",3]],["result",6]]],[11,"fmt","dfw::nftables::types","",14,[[["formatter",3]],["result",6]]],[11,"fmt","","",15,[[["formatter",3]],["result",6]]],[11,"fmt","","",16,[[["formatter",3]],["result",6]]],[11,"fmt","dfw::nftables","",39,[[["formatter",3]],["result",6]]],[11,"fmt","","",11,[[["formatter",3]],["result",6]]],[11,"fmt","","",12,[[["formatter",3]],["result",6]]],[11,"fmt","","",13,[[["formatter",3]],["result",6]]],[11,"fmt","dfw::process","",18,[[["formatter",3]],["result",6]]],[11,"fmt","","",17,[[["formatter",3]],["result",6]]],[11,"fmt","dfw::types","",21,[[["formatter",3]],["result",6]]],[11,"fmt","","",22,[[["formatter",3]],["result",6]]],[11,"fmt","","",23,[[["formatter",3]],["result",6]]],[11,"fmt","","",24,[[["formatter",3]],["result",6]]],[11,"fmt","","",25,[[["formatter",3]],["result",6]]],[11,"fmt","","",26,[[["formatter",3]],["result",6]]],[11,"fmt","","",27,[[["formatter",3]],["result",6]]],[11,"fmt","","",28,[[["formatter",3]],["result",6]]],[11,"fmt","","",29,[[["formatter",3]],["result",6]]],[11,"fmt","","",30,[[["formatter",3]],["result",6]]],[11,"fmt","","",31,[[["formatter",3]],["result",6]]],[11,"fmt","","",33,[[["formatter",3]],["result",6]]],[11,"fmt","","",34,[[["formatter",3]],["result",6]]],[11,"fmt","","",35,[[["formatter",3]],["result",6]]],[11,"fmt","","",36,[[["formatter",3]],["result",6]]],[11,"fmt","dfw::errors","",0,[[["formatter",3]],["result",6]]],[11,"fmt","dfw::nftables","",11,[[["formatter",3]],[["result",4],["error",3]]]],[11,"fmt","","",12,[[["formatter",3]],[["result",4],["error",3]]]],[11,"fmt","","",13,[[["formatter",3]],[["result",4],["error",3]]]],[11,"fmt","dfw::types","",35,[[["formatter",3]],[["result",4],["error",3]]]],[11,"fmt","","",36,[[["formatter",3]],[["result",4],["error",3]]]],[11,"hash","dfw::nftables::types","",15,[[]]],[11,"hash","dfw::types","",22,[[]]],[11,"hash","","",23,[[]]],[11,"hash","","",24,[[]]],[11,"hash","","",25,[[]]],[11,"hash","","",26,[[]]],[11,"hash","","",27,[[]]],[11,"hash","","",28,[[]]],[11,"hash","","",29,[[]]],[11,"hash","","",30,[[]]],[11,"hash","","",31,[[]]],[11,"hash","","",33,[[]]],[11,"hash","","",34,[[]]],[11,"hash","","",35,[[]]],[11,"hash","","",36,[[]]],[11,"from_str","","Convert a formatted string into a `ExposePort`.",31,[[],["result",4]]],[11,"from_str","","",35,[[],[["result",4],["chainpolicy",4]]]],[11,"from_str","","",36,[[],[["ruleverdict",4],["result",4]]]],[11,"deserialize","dfw::iptables::types","",8,[[],["result",4]]],[11,"deserialize","","",9,[[],["result",4]]],[11,"deserialize","dfw::nftables::types","",14,[[],["result",4]]],[11,"deserialize","","",15,[[],["result",4]]],[11,"deserialize","","",16,[[],["result",4]]],[11,"deserialize","dfw::types","",21,[[],["result",4]]],[11,"deserialize","","",22,[[],["result",4]]],[11,"deserialize","","",23,[[],["result",4]]],[11,"deserialize","","",24,[[],["result",4]]],[11,"deserialize","","",25,[[],["result",4]]],[11,"deserialize","","",26,[[],["result",4]]],[11,"deserialize","","",27,[[],["result",4]]],[11,"deserialize","","",28,[[],["result",4]]],[11,"deserialize","","",29,[[],["result",4]]],[11,"deserialize","","",30,[[],["result",4]]],[11,"deserialize","","",31,[[],["result",4]]],[11,"deserialize","","",33,[[],["result",4]]],[11,"deserialize","","",34,[[],["result",4]]],[11,"deserialize","","",35,[[],["result",4]]],[11,"deserialize","","",36,[[],["result",4]]],[11,"name","dfw::errors","",0,[[],["option",4]]],[11,"cause","","",0,[[],[["option",4],["fail",8]]]],[11,"backtrace","","",0,[[],[["option",4],["backtrace",3]]]],[11,"serialize","dfw::types","",35,[[["key",6],["serializer",8],["record",3]],["result",6]]],[11,"serialize","","",36,[[["key",6],["serializer",8],["record",3]],["result",6]]]],"p":[[4,"DFWError"],[13,"NFTablesError"],[13,"TraitMethodUnimplemented"],[4,"IptablesRule"],[4,"IptablesRuleDiscriminants"],[4,"PolicyOrRule"],[13,"Policy"],[13,"Rule"],[3,"Defaults"],[3,"Initialization"],[3,"Iptables"],[4,"Family"],[4,"Type"],[4,"Hook"],[3,"Defaults"],[3,"Table"],[3,"Initialization"],[3,"ProcessingOptions"],[4,"ContainerFilter"],[8,"Process"],[3,"ProcessContext"],[3,"DFW"],[3,"GlobalDefaults"],[3,"ContainerToContainer"],[3,"ContainerToContainerRule"],[3,"ContainerToWiderWorld"],[3,"ContainerToWiderWorldRule"],[3,"ContainerToHost"],[3,"ContainerToHostRule"],[3,"WiderWorldToContainer"],[3,"WiderWorldToContainerRule"],[3,"ExposePort"],[3,"ExposePortBuilder"],[3,"ContainerDNAT"],[3,"ContainerDNATRule"],[4,"ChainPolicy"],[4,"RuleVerdict"],[8,"FutureExt"],[8,"FirewallBackend"],[3,"Nftables"]]}\
}');
addSearchOptions(searchIndex);initSearch(searchIndex);