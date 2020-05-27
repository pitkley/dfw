var searchIndex={};
searchIndex["dfw"] = {"doc":"DFW - Docker Firewall Framework in Rust","i":[[0,"errors","dfw","Errors, using [`failure`][failure].",null,null],[4,"DFWError","dfw::errors","",null,null],[13,"NFTablesError","","",0,null],[12,"stdout","dfw::errors::DFWError","",1,null],[12,"stderr","","",1,null],[13,"TraitMethodUnimplemented","dfw::errors","",0,null],[12,"method","dfw::errors::DFWError","",2,null],[6,"Result","dfw::errors","",null,null],[0,"nftables","dfw","This module abstracts various nftables concepts into…",null,null],[4,"Family","dfw::nftables","Represenation of nftables table-families.",null,null],[13,"Ip","","IPv4 table family",3,null],[13,"Ip6","","IPv6 table family",3,null],[13,"Inet","","Dualstack IPv4/IPv6 table family",3,null],[13,"Arp","","ARP table family",3,null],[13,"Bridge","","Bridge table family",3,null],[13,"Netdev","","Netdev table family",3,null],[4,"Type","","Representation of nftables chain-types.",null,null],[13,"Filter","","Is used to filter packets.",4,null],[13,"Route","","Is used to reroute packets if any relevant IP header field…",4,null],[13,"Nat","","Is used to perform Networking Address Translation (NAT).",4,null],[4,"Hook","","Representation of nftables chain hooks.",null,null],[13,"Ingress","","Ingress allows traffic-filtering before pre-routing, after…",5,null],[13,"Prerouting","","Prerouting allows traffic-filtering before the packets…",5,null],[13,"Input","","Input allows traffic-filtering for packets that have been…",5,null],[13,"Forward","","Forward allows traffic-filtering for packets that were not…",5,null],[13,"Output","","Output allows traffic-filtering for packets leaving the…",5,null],[13,"Postrouting","","Postrouting allows traffic-filtering for already routed…",5,null],[4,"ChainPolicy","","Representation of nftables chain policies.",null,null],[13,"Accept","","The accept verdict means that the packet will keep…",6,null],[13,"Drop","","The drop verdict means that the packet is discarded if the…",6,null],[4,"RuleVerdict","","Representation of nftables rule policies.",null,null],[13,"Accept","","The accept verdict means that the packet will keep…",7,null],[13,"Drop","","The drop verdict means that the packet is discarded if the…",7,null],[13,"Reject","","The reject verdict means that the packet is responded to…",7,null],[5,"add_table","","Construct nft command for adding a table.",null,[[["str"],["family"]],["string"]]],[5,"flush_table","","Construct nft command for flushing a table.",null,[[["str"],["family"]],["string"]]],[5,"delete_table","","Construct nft command for deleting a table.",null,[[["str"],["family"]],["string"]]],[5,"add_chain","","Construct nft command for adding a base chain.",null,[[["str"],["family"]],["string"]]],[5,"add_base_chain","","Construct nft command for adding a base chain.",null,[[["str"],["type"],["hook"],["family"],["i16"]],["string"]]],[5,"set_chain_policy","","Construct nft command for setting the policy for a chain.",null,[[["str"],["chainpolicy"],["family"]],["string"]]],[5,"add_rule","","Construct nft command for adding a rule to a chain.",null,[[["str"],["family"]],["string"]]],[5,"insert_rule","","Construct nft command for inserting a rule into a chain.",null,[[["str"],["u32"],["family"],["option",["u32"]]],["string"]]],[0,"process","dfw","This module holds the types related to configuration…",null,null],[3,"ProcessContext","dfw::process","Enclosing struct to manage rule processing.",null,null],[3,"ProcessingOptions","","Options to configure the processing procedure.",null,null],[12,"container_filter","","Option to filter the containers to be processed, see…",8,null],[4,"ContainerFilter","","Option to filter the containers to be processed",null,null],[13,"All","","Process all containers, i.e. don't filter.",9,null],[13,"Running","","Only process running containers.",9,null],[8,"Process","","This trait allows a type to define its own processing…",null,null],[10,"process","","Process the current type within the given…",10,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"new","","Create a new instance of `ProcessDFW` for rule processing.",11,[[["bool"],["dfw"],["logger"],["processingoptions"],["docker"]],[["result",["processcontext"]],["processcontext"]]]],[11,"process","","Start the processing using the configuration given at…",11,[[["self"]],["result"]]],[11,"marker_in_current_ruleset","","Check if the provided string-marker is part of the current…",11,[[["str"],["self"]],["bool"]]],[0,"rule","dfw","TODO: write documentation",null,null],[3,"Rule","dfw::rule","",null,null],[12,"in_interface","","",12,null],[12,"out_interface","","",12,null],[12,"source_address","","",12,null],[12,"destination_address","","",12,null],[12,"source_address_v6","","",12,null],[12,"destination_address_v6","","",12,null],[12,"protocol","","",12,null],[12,"source_port","","",12,null],[12,"destination_port","","",12,null],[12,"matches","","",12,null],[12,"comment","","",12,null],[12,"verdict","","",12,null],[12,"dnat","","",12,null],[3,"RuleBuilder","","Builder for `Rule`.",null,null],[11,"in_interface","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"out_interface","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"source_address","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"destination_address","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"source_address_v6","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"destination_address_v6","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"protocol","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"source_port","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"destination_port","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"matches","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"comment","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"verdict","","",13,[[["ruleverdict"],["self"],["into",["ruleverdict"]]],["self"]]],[11,"dnat","","",13,[[["self"],["into",["string"]],["string"]],["self"]]],[11,"build","","",13,[[["self"]],[["result",["string"]],["string"]]]],[0,"types","dfw","The types in this module make up the structure of the…",null,null],[3,"DFW","dfw::types","`DFW` is the parent type defining the complete…",null,null],[12,"defaults","","The `defaults` configuration section",14,null],[12,"initialization","","The `initialization` configuration section",14,null],[12,"container_to_container","","The `container_to_container` configuration section",14,null],[12,"container_to_wider_world","","The `container_to_wider_world` configuration section",14,null],[12,"container_to_host","","The `container_to_host` configuration section",14,null],[12,"wider_world_to_container","","The `wider_world_to_container` configuration section",14,null],[12,"container_dnat","","The `container_dnat` configuration section",14,null],[3,"Defaults","","The default configuration section, used by DFW for rule…",null,null],[12,"custom_tables","","Specify the names of custom nft-tables that should be…",15,null],[12,"external_network_interfaces","","This defines the external network interfaces of the host…",15,null],[12,"default_docker_bridge_to_host_policy","","This defines whether the default Docker bridge (usually…",15,null],[3,"Table","","Reference to an nftables table, specifically to the input-…",null,null],[12,"name","","Name of the custom table.",16,null],[12,"chains","","Names of the input and forward chains defined within the…",16,null],[3,"Initialization","","The initialization section allows you to execute any…",null,null],[12,"rules","","Initialization rules for nftables",17,null],[3,"ContainerToContainer","","The container-to-container section, defining how…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",18,null],[12,"rules","","An optional list of rules, see `ContainerToContainerRule`.",18,null],[3,"ContainerToContainerRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Common network between the source container and the…",19,null],[12,"src_container","","Source container to apply the rule to.",19,null],[12,"dst_container","","Destination container to apply the rule to.",19,null],[12,"matches","","Additional match-string, which will be added to the…",19,null],[12,"verdict","","Verdict for rule (accept, drop or reject).",19,null],[3,"ContainerToWiderWorld","","The container-to-wider-world section, defining how…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",20,null],[12,"rules","","An optional list of rules, see `ContainerToWiderWorldRule`.",20,null],[3,"ContainerToWiderWorldRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Network of the source container to apply the rule to.",21,null],[12,"src_container","","Source container to apply the rule to.",21,null],[12,"matches","","Additional match-string, which will be added to the…",21,null],[12,"verdict","","Verdict for rule (accept, drop or reject).",21,null],[12,"external_network_interface","","Specific external network interface to target.",21,null],[3,"ContainerToHost","","The container-to-host section, defining how containers can…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",22,null],[12,"rules","","An optional list of rules, see `ContainerToHostRule`.",22,null],[3,"ContainerToHostRule","","Definition for a rule to be used in the container-to-host…",null,null],[12,"network","","Network of the source container to apply the rule to.",23,null],[12,"src_container","","Source container to apply the rule to.",23,null],[12,"matches","","Additional match-string, which will be added to the…",23,null],[12,"verdict","","Verdict for rule (accept, drop or reject).",23,null],[3,"WiderWorldToContainer","","The wider-world-to-container section, defining how…",null,null],[12,"rules","","An optional list of rules, see `WiderWorldToContainerRule`.",24,null],[3,"WiderWorldToContainerRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Network of the destination container to apply the rule to.",25,null],[12,"dst_container","","Destination container to apply the rule to.",25,null],[12,"expose_port","","Ports to apply the rule to.",25,null],[12,"external_network_interface","","Specific external network interface to target.",25,null],[12,"source_cidr_v4","","Source CIDRs (IPv4) to which incoming traffic should be…",25,null],[12,"source_cidr_v6","","Source CIDRs (IPv6) to which incoming traffic should be…",25,null],[3,"ExposePort","","Struct to hold a port definition to expose on the…",null,null],[12,"host_port","","Port the `container_port` should be exposed to on the host.",26,null],[12,"container_port","","Port the `host_port` should map to into the container.",26,null],[12,"family","","Family of the exposed port.",26,null],[3,"ExposePortBuilder","","Builder for `ExposePort`.",null,null],[12,"host_port","","Port the `container_port` should be exposed to on the host.",27,null],[12,"container_port","","Port the `host_port` should map to into the container.",27,null],[12,"family","","Family of the exposed port.",27,null],[3,"ContainerDNAT","","The container-DNAT section, defining how containers can…",null,null],[12,"rules","","An optional list of rules, see `ContainerDNATRule`.",28,null],[3,"ContainerDNATRule","","Definition for a rule to be used in the container-DNAT…",null,null],[12,"src_network","","Network of the source container to apply the rule to.",29,null],[12,"src_container","","Source container to apply the rule to.",29,null],[12,"dst_network","","Network of the destination container to apply the rule to.",29,null],[12,"dst_container","","Destination container to apply the rule to.",29,null],[12,"expose_port","","Ports to apply the rule to.",29,null],[11,"host_port","","Port the `container_port` should be exposed to on the host.",27,[[["u16"],["self"]],["self"]]],[11,"container_port","","Port the `host_port` should map to into the container.",27,[[["option",["u16"]],["self"],["u16"]],["self"]]],[11,"family","","Family of the exposed port.",27,[[["self"],["string"]],["self"]]],[11,"build","","Builds a new `ExposePort`.",27,[[["self"]],[["string"],["result",["exposeport","string"]],["exposeport"]]]],[0,"util","dfw","Utilities module",null,null],[5,"load_file","dfw::util","Load single TOML-file from path and deserialize it into…",null,[[["str"]],["result"]]],[5,"load_path","","Load all TOML-files from a path, concatenate their…",null,[[["str"]],["result"]]],[8,"FutureExt","","An extension trait for `Future` allowing synchronized…",null,null],[11,"sync","","Execute future synchronously, blocking until a result can…",30,[[],["result"]]],[11,"from","dfw::errors","",0,[[["t"]],["t"]]],[11,"into","","",0,[[],["u"]]],[11,"to_string","","",0,[[["self"]],["string"]]],[11,"try_from","","",0,[[["u"]],["result"]]],[11,"try_into","","",0,[[],["result"]]],[11,"borrow","","",0,[[["self"]],["t"]]],[11,"borrow_mut","","",0,[[["self"]],["t"]]],[11,"type_id","","",0,[[["self"]],["typeid"]]],[11,"as_fail","","",0,[[["self"]],["fail"]]],[11,"vzip","","",0,[[],["v"]]],[11,"from","dfw::nftables","",3,[[["t"]],["t"]]],[11,"into","","",3,[[],["u"]]],[11,"to_owned","","",3,[[["self"]],["t"]]],[11,"clone_into","","",3,[[["self"],["t"]]]],[11,"to_string","","",3,[[["self"]],["string"]]],[11,"try_from","","",3,[[["u"]],["result"]]],[11,"try_into","","",3,[[],["result"]]],[11,"borrow","","",3,[[["self"]],["t"]]],[11,"borrow_mut","","",3,[[["self"]],["t"]]],[11,"type_id","","",3,[[["self"]],["typeid"]]],[11,"vzip","","",3,[[],["v"]]],[11,"from","","",4,[[["t"]],["t"]]],[11,"into","","",4,[[],["u"]]],[11,"to_owned","","",4,[[["self"]],["t"]]],[11,"clone_into","","",4,[[["self"],["t"]]]],[11,"to_string","","",4,[[["self"]],["string"]]],[11,"try_from","","",4,[[["u"]],["result"]]],[11,"try_into","","",4,[[],["result"]]],[11,"borrow","","",4,[[["self"]],["t"]]],[11,"borrow_mut","","",4,[[["self"]],["t"]]],[11,"type_id","","",4,[[["self"]],["typeid"]]],[11,"vzip","","",4,[[],["v"]]],[11,"from","","",5,[[["t"]],["t"]]],[11,"into","","",5,[[],["u"]]],[11,"to_owned","","",5,[[["self"]],["t"]]],[11,"clone_into","","",5,[[["self"],["t"]]]],[11,"to_string","","",5,[[["self"]],["string"]]],[11,"try_from","","",5,[[["u"]],["result"]]],[11,"try_into","","",5,[[],["result"]]],[11,"borrow","","",5,[[["self"]],["t"]]],[11,"borrow_mut","","",5,[[["self"]],["t"]]],[11,"type_id","","",5,[[["self"]],["typeid"]]],[11,"vzip","","",5,[[],["v"]]],[11,"from","","",6,[[["t"]],["t"]]],[11,"into","","",6,[[],["u"]]],[11,"to_owned","","",6,[[["self"]],["t"]]],[11,"clone_into","","",6,[[["self"],["t"]]]],[11,"to_string","","",6,[[["self"]],["string"]]],[11,"try_from","","",6,[[["u"]],["result"]]],[11,"try_into","","",6,[[],["result"]]],[11,"borrow","","",6,[[["self"]],["t"]]],[11,"borrow_mut","","",6,[[["self"]],["t"]]],[11,"type_id","","",6,[[["self"]],["typeid"]]],[11,"equivalent","","",6,[[["k"],["self"]],["bool"]]],[11,"vzip","","",6,[[],["v"]]],[11,"from","","",7,[[["t"]],["t"]]],[11,"into","","",7,[[],["u"]]],[11,"to_owned","","",7,[[["self"]],["t"]]],[11,"clone_into","","",7,[[["self"],["t"]]]],[11,"to_string","","",7,[[["self"]],["string"]]],[11,"try_from","","",7,[[["u"]],["result"]]],[11,"try_into","","",7,[[],["result"]]],[11,"borrow","","",7,[[["self"]],["t"]]],[11,"borrow_mut","","",7,[[["self"]],["t"]]],[11,"type_id","","",7,[[["self"]],["typeid"]]],[11,"equivalent","","",7,[[["k"],["self"]],["bool"]]],[11,"vzip","","",7,[[],["v"]]],[11,"from","dfw::process","",11,[[["t"]],["t"]]],[11,"into","","",11,[[],["u"]]],[11,"try_from","","",11,[[["u"]],["result"]]],[11,"try_into","","",11,[[],["result"]]],[11,"borrow","","",11,[[["self"]],["t"]]],[11,"borrow_mut","","",11,[[["self"]],["t"]]],[11,"type_id","","",11,[[["self"]],["typeid"]]],[11,"vzip","","",11,[[],["v"]]],[11,"from","","",8,[[["t"]],["t"]]],[11,"into","","",8,[[],["u"]]],[11,"to_owned","","",8,[[["self"]],["t"]]],[11,"clone_into","","",8,[[["self"],["t"]]]],[11,"try_from","","",8,[[["u"]],["result"]]],[11,"try_into","","",8,[[],["result"]]],[11,"borrow","","",8,[[["self"]],["t"]]],[11,"borrow_mut","","",8,[[["self"]],["t"]]],[11,"type_id","","",8,[[["self"]],["typeid"]]],[11,"equivalent","","",8,[[["k"],["self"]],["bool"]]],[11,"vzip","","",8,[[],["v"]]],[11,"from","","",9,[[["t"]],["t"]]],[11,"into","","",9,[[],["u"]]],[11,"to_owned","","",9,[[["self"]],["t"]]],[11,"clone_into","","",9,[[["self"],["t"]]]],[11,"try_from","","",9,[[["u"]],["result"]]],[11,"try_into","","",9,[[],["result"]]],[11,"borrow","","",9,[[["self"]],["t"]]],[11,"borrow_mut","","",9,[[["self"]],["t"]]],[11,"type_id","","",9,[[["self"]],["typeid"]]],[11,"equivalent","","",9,[[["k"],["self"]],["bool"]]],[11,"vzip","","",9,[[],["v"]]],[11,"from","dfw::rule","",12,[[["t"]],["t"]]],[11,"into","","",12,[[],["u"]]],[11,"to_owned","","",12,[[["self"]],["t"]]],[11,"clone_into","","",12,[[["self"],["t"]]]],[11,"try_from","","",12,[[["u"]],["result"]]],[11,"try_into","","",12,[[],["result"]]],[11,"borrow","","",12,[[["self"]],["t"]]],[11,"borrow_mut","","",12,[[["self"]],["t"]]],[11,"type_id","","",12,[[["self"]],["typeid"]]],[11,"vzip","","",12,[[],["v"]]],[11,"from","","",13,[[["t"]],["t"]]],[11,"into","","",13,[[],["u"]]],[11,"to_owned","","",13,[[["self"]],["t"]]],[11,"clone_into","","",13,[[["self"],["t"]]]],[11,"try_from","","",13,[[["u"]],["result"]]],[11,"try_into","","",13,[[],["result"]]],[11,"borrow","","",13,[[["self"]],["t"]]],[11,"borrow_mut","","",13,[[["self"]],["t"]]],[11,"type_id","","",13,[[["self"]],["typeid"]]],[11,"vzip","","",13,[[],["v"]]],[11,"from","dfw::types","",14,[[["t"]],["t"]]],[11,"into","","",14,[[],["u"]]],[11,"to_owned","","",14,[[["self"]],["t"]]],[11,"clone_into","","",14,[[["self"],["t"]]]],[11,"try_from","","",14,[[["u"]],["result"]]],[11,"try_into","","",14,[[],["result"]]],[11,"borrow","","",14,[[["self"]],["t"]]],[11,"borrow_mut","","",14,[[["self"]],["t"]]],[11,"type_id","","",14,[[["self"]],["typeid"]]],[11,"equivalent","","",14,[[["k"],["self"]],["bool"]]],[11,"vzip","","",14,[[],["v"]]],[11,"from","","",15,[[["t"]],["t"]]],[11,"into","","",15,[[],["u"]]],[11,"to_owned","","",15,[[["self"]],["t"]]],[11,"clone_into","","",15,[[["self"],["t"]]]],[11,"try_from","","",15,[[["u"]],["result"]]],[11,"try_into","","",15,[[],["result"]]],[11,"borrow","","",15,[[["self"]],["t"]]],[11,"borrow_mut","","",15,[[["self"]],["t"]]],[11,"type_id","","",15,[[["self"]],["typeid"]]],[11,"equivalent","","",15,[[["k"],["self"]],["bool"]]],[11,"vzip","","",15,[[],["v"]]],[11,"from","","",16,[[["t"]],["t"]]],[11,"into","","",16,[[],["u"]]],[11,"to_owned","","",16,[[["self"]],["t"]]],[11,"clone_into","","",16,[[["self"],["t"]]]],[11,"try_from","","",16,[[["u"]],["result"]]],[11,"try_into","","",16,[[],["result"]]],[11,"borrow","","",16,[[["self"]],["t"]]],[11,"borrow_mut","","",16,[[["self"]],["t"]]],[11,"type_id","","",16,[[["self"]],["typeid"]]],[11,"equivalent","","",16,[[["k"],["self"]],["bool"]]],[11,"vzip","","",16,[[],["v"]]],[11,"from","","",17,[[["t"]],["t"]]],[11,"into","","",17,[[],["u"]]],[11,"to_owned","","",17,[[["self"]],["t"]]],[11,"clone_into","","",17,[[["self"],["t"]]]],[11,"try_from","","",17,[[["u"]],["result"]]],[11,"try_into","","",17,[[],["result"]]],[11,"borrow","","",17,[[["self"]],["t"]]],[11,"borrow_mut","","",17,[[["self"]],["t"]]],[11,"type_id","","",17,[[["self"]],["typeid"]]],[11,"equivalent","","",17,[[["k"],["self"]],["bool"]]],[11,"vzip","","",17,[[],["v"]]],[11,"from","","",18,[[["t"]],["t"]]],[11,"into","","",18,[[],["u"]]],[11,"to_owned","","",18,[[["self"]],["t"]]],[11,"clone_into","","",18,[[["self"],["t"]]]],[11,"try_from","","",18,[[["u"]],["result"]]],[11,"try_into","","",18,[[],["result"]]],[11,"borrow","","",18,[[["self"]],["t"]]],[11,"borrow_mut","","",18,[[["self"]],["t"]]],[11,"type_id","","",18,[[["self"]],["typeid"]]],[11,"equivalent","","",18,[[["k"],["self"]],["bool"]]],[11,"vzip","","",18,[[],["v"]]],[11,"from","","",19,[[["t"]],["t"]]],[11,"into","","",19,[[],["u"]]],[11,"to_owned","","",19,[[["self"]],["t"]]],[11,"clone_into","","",19,[[["self"],["t"]]]],[11,"try_from","","",19,[[["u"]],["result"]]],[11,"try_into","","",19,[[],["result"]]],[11,"borrow","","",19,[[["self"]],["t"]]],[11,"borrow_mut","","",19,[[["self"]],["t"]]],[11,"type_id","","",19,[[["self"]],["typeid"]]],[11,"equivalent","","",19,[[["k"],["self"]],["bool"]]],[11,"vzip","","",19,[[],["v"]]],[11,"from","","",20,[[["t"]],["t"]]],[11,"into","","",20,[[],["u"]]],[11,"to_owned","","",20,[[["self"]],["t"]]],[11,"clone_into","","",20,[[["self"],["t"]]]],[11,"try_from","","",20,[[["u"]],["result"]]],[11,"try_into","","",20,[[],["result"]]],[11,"borrow","","",20,[[["self"]],["t"]]],[11,"borrow_mut","","",20,[[["self"]],["t"]]],[11,"type_id","","",20,[[["self"]],["typeid"]]],[11,"equivalent","","",20,[[["k"],["self"]],["bool"]]],[11,"vzip","","",20,[[],["v"]]],[11,"from","","",21,[[["t"]],["t"]]],[11,"into","","",21,[[],["u"]]],[11,"to_owned","","",21,[[["self"]],["t"]]],[11,"clone_into","","",21,[[["self"],["t"]]]],[11,"try_from","","",21,[[["u"]],["result"]]],[11,"try_into","","",21,[[],["result"]]],[11,"borrow","","",21,[[["self"]],["t"]]],[11,"borrow_mut","","",21,[[["self"]],["t"]]],[11,"type_id","","",21,[[["self"]],["typeid"]]],[11,"equivalent","","",21,[[["k"],["self"]],["bool"]]],[11,"vzip","","",21,[[],["v"]]],[11,"from","","",22,[[["t"]],["t"]]],[11,"into","","",22,[[],["u"]]],[11,"to_owned","","",22,[[["self"]],["t"]]],[11,"clone_into","","",22,[[["self"],["t"]]]],[11,"try_from","","",22,[[["u"]],["result"]]],[11,"try_into","","",22,[[],["result"]]],[11,"borrow","","",22,[[["self"]],["t"]]],[11,"borrow_mut","","",22,[[["self"]],["t"]]],[11,"type_id","","",22,[[["self"]],["typeid"]]],[11,"equivalent","","",22,[[["k"],["self"]],["bool"]]],[11,"vzip","","",22,[[],["v"]]],[11,"from","","",23,[[["t"]],["t"]]],[11,"into","","",23,[[],["u"]]],[11,"to_owned","","",23,[[["self"]],["t"]]],[11,"clone_into","","",23,[[["self"],["t"]]]],[11,"try_from","","",23,[[["u"]],["result"]]],[11,"try_into","","",23,[[],["result"]]],[11,"borrow","","",23,[[["self"]],["t"]]],[11,"borrow_mut","","",23,[[["self"]],["t"]]],[11,"type_id","","",23,[[["self"]],["typeid"]]],[11,"equivalent","","",23,[[["k"],["self"]],["bool"]]],[11,"vzip","","",23,[[],["v"]]],[11,"from","","",24,[[["t"]],["t"]]],[11,"into","","",24,[[],["u"]]],[11,"to_owned","","",24,[[["self"]],["t"]]],[11,"clone_into","","",24,[[["self"],["t"]]]],[11,"try_from","","",24,[[["u"]],["result"]]],[11,"try_into","","",24,[[],["result"]]],[11,"borrow","","",24,[[["self"]],["t"]]],[11,"borrow_mut","","",24,[[["self"]],["t"]]],[11,"type_id","","",24,[[["self"]],["typeid"]]],[11,"equivalent","","",24,[[["k"],["self"]],["bool"]]],[11,"vzip","","",24,[[],["v"]]],[11,"from","","",25,[[["t"]],["t"]]],[11,"into","","",25,[[],["u"]]],[11,"to_owned","","",25,[[["self"]],["t"]]],[11,"clone_into","","",25,[[["self"],["t"]]]],[11,"try_from","","",25,[[["u"]],["result"]]],[11,"try_into","","",25,[[],["result"]]],[11,"borrow","","",25,[[["self"]],["t"]]],[11,"borrow_mut","","",25,[[["self"]],["t"]]],[11,"type_id","","",25,[[["self"]],["typeid"]]],[11,"equivalent","","",25,[[["k"],["self"]],["bool"]]],[11,"vzip","","",25,[[],["v"]]],[11,"from","","",26,[[["t"]],["t"]]],[11,"into","","",26,[[],["u"]]],[11,"to_owned","","",26,[[["self"]],["t"]]],[11,"clone_into","","",26,[[["self"],["t"]]]],[11,"try_from","","",26,[[["u"]],["result"]]],[11,"try_into","","",26,[[],["result"]]],[11,"borrow","","",26,[[["self"]],["t"]]],[11,"borrow_mut","","",26,[[["self"]],["t"]]],[11,"type_id","","",26,[[["self"]],["typeid"]]],[11,"equivalent","","",26,[[["k"],["self"]],["bool"]]],[11,"vzip","","",26,[[],["v"]]],[11,"from","","",27,[[["t"]],["t"]]],[11,"into","","",27,[[],["u"]]],[11,"to_owned","","",27,[[["self"]],["t"]]],[11,"clone_into","","",27,[[["self"],["t"]]]],[11,"try_from","","",27,[[["u"]],["result"]]],[11,"try_into","","",27,[[],["result"]]],[11,"borrow","","",27,[[["self"]],["t"]]],[11,"borrow_mut","","",27,[[["self"]],["t"]]],[11,"type_id","","",27,[[["self"]],["typeid"]]],[11,"vzip","","",27,[[],["v"]]],[11,"from","","",28,[[["t"]],["t"]]],[11,"into","","",28,[[],["u"]]],[11,"to_owned","","",28,[[["self"]],["t"]]],[11,"clone_into","","",28,[[["self"],["t"]]]],[11,"try_from","","",28,[[["u"]],["result"]]],[11,"try_into","","",28,[[],["result"]]],[11,"borrow","","",28,[[["self"]],["t"]]],[11,"borrow_mut","","",28,[[["self"]],["t"]]],[11,"type_id","","",28,[[["self"]],["typeid"]]],[11,"equivalent","","",28,[[["k"],["self"]],["bool"]]],[11,"vzip","","",28,[[],["v"]]],[11,"from","","",29,[[["t"]],["t"]]],[11,"into","","",29,[[],["u"]]],[11,"to_owned","","",29,[[["self"]],["t"]]],[11,"clone_into","","",29,[[["self"],["t"]]]],[11,"try_from","","",29,[[["u"]],["result"]]],[11,"try_into","","",29,[[],["result"]]],[11,"borrow","","",29,[[["self"]],["t"]]],[11,"borrow_mut","","",29,[[["self"]],["t"]]],[11,"type_id","","",29,[[["self"]],["typeid"]]],[11,"equivalent","","",29,[[["k"],["self"]],["bool"]]],[11,"vzip","","",29,[[],["v"]]],[11,"process","","",14,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",17,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",15,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",18,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",19,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",20,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",21,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",22,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",23,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",24,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",25,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",28,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"process","","",29,[[["self"],["processcontext"]],[["result",["option"]],["option",["vec"]]]]],[11,"clone","dfw::nftables","",3,[[["self"]],["family"]]],[11,"clone","","",4,[[["self"]],["type"]]],[11,"clone","","",5,[[["self"]],["hook"]]],[11,"clone","","",6,[[["self"]],["chainpolicy"]]],[11,"clone","","",7,[[["self"]],["ruleverdict"]]],[11,"clone","dfw::process","",9,[[["self"]],["containerfilter"]]],[11,"clone","","",8,[[["self"]],["processingoptions"]]],[11,"clone","dfw::rule","",12,[[["self"]],["rule"]]],[11,"clone","","",13,[[["self"]],["rulebuilder"]]],[11,"clone","dfw::types","",14,[[["self"]],["dfw"]]],[11,"clone","","",15,[[["self"]],["defaults"]]],[11,"clone","","",16,[[["self"]],["table"]]],[11,"clone","","",17,[[["self"]],["initialization"]]],[11,"clone","","",18,[[["self"]],["containertocontainer"]]],[11,"clone","","",19,[[["self"]],["containertocontainerrule"]]],[11,"clone","","",20,[[["self"]],["containertowiderworld"]]],[11,"clone","","",21,[[["self"]],["containertowiderworldrule"]]],[11,"clone","","",22,[[["self"]],["containertohost"]]],[11,"clone","","",23,[[["self"]],["containertohostrule"]]],[11,"clone","","",24,[[["self"]],["widerworldtocontainer"]]],[11,"clone","","",25,[[["self"]],["widerworldtocontainerrule"]]],[11,"clone","","",26,[[["self"]],["exposeport"]]],[11,"clone","","",27,[[["self"]],["exposeportbuilder"]]],[11,"clone","","",28,[[["self"]],["containerdnat"]]],[11,"clone","","",29,[[["self"]],["containerdnatrule"]]],[11,"default","dfw::nftables","",6,[[],["chainpolicy"]]],[11,"default","","",7,[[],["ruleverdict"]]],[11,"default","dfw::process","",8,[[],["self"]]],[11,"default","dfw::rule","",13,[[],["rulebuilder"]]],[11,"default","dfw::types","",15,[[],["defaults"]]],[11,"default","","",16,[[],["table"]]],[11,"default","","",17,[[],["initialization"]]],[11,"default","","",26,[[],["exposeport"]]],[11,"default","","",27,[[],["exposeportbuilder"]]],[11,"eq","dfw::nftables","",6,[[["self"],["chainpolicy"]],["bool"]]],[11,"eq","","",7,[[["self"],["ruleverdict"]],["bool"]]],[11,"eq","dfw::process","",9,[[["self"],["containerfilter"]],["bool"]]],[11,"eq","","",8,[[["processingoptions"],["self"]],["bool"]]],[11,"ne","","",8,[[["processingoptions"],["self"]],["bool"]]],[11,"eq","dfw::types","",14,[[["dfw"],["self"]],["bool"]]],[11,"ne","","",14,[[["dfw"],["self"]],["bool"]]],[11,"eq","","",15,[[["defaults"],["self"]],["bool"]]],[11,"ne","","",15,[[["defaults"],["self"]],["bool"]]],[11,"eq","","",16,[[["self"],["table"]],["bool"]]],[11,"ne","","",16,[[["self"],["table"]],["bool"]]],[11,"eq","","",17,[[["self"],["initialization"]],["bool"]]],[11,"ne","","",17,[[["self"],["initialization"]],["bool"]]],[11,"eq","","",18,[[["self"],["containertocontainer"]],["bool"]]],[11,"ne","","",18,[[["self"],["containertocontainer"]],["bool"]]],[11,"eq","","",19,[[["containertocontainerrule"],["self"]],["bool"]]],[11,"ne","","",19,[[["containertocontainerrule"],["self"]],["bool"]]],[11,"eq","","",20,[[["containertowiderworld"],["self"]],["bool"]]],[11,"ne","","",20,[[["containertowiderworld"],["self"]],["bool"]]],[11,"eq","","",21,[[["containertowiderworldrule"],["self"]],["bool"]]],[11,"ne","","",21,[[["containertowiderworldrule"],["self"]],["bool"]]],[11,"eq","","",22,[[["self"],["containertohost"]],["bool"]]],[11,"ne","","",22,[[["self"],["containertohost"]],["bool"]]],[11,"eq","","",23,[[["self"],["containertohostrule"]],["bool"]]],[11,"ne","","",23,[[["self"],["containertohostrule"]],["bool"]]],[11,"eq","","",24,[[["self"],["widerworldtocontainer"]],["bool"]]],[11,"ne","","",24,[[["self"],["widerworldtocontainer"]],["bool"]]],[11,"eq","","",25,[[["self"],["widerworldtocontainerrule"]],["bool"]]],[11,"ne","","",25,[[["self"],["widerworldtocontainerrule"]],["bool"]]],[11,"eq","","",26,[[["self"],["exposeport"]],["bool"]]],[11,"ne","","",26,[[["self"],["exposeport"]],["bool"]]],[11,"eq","","",28,[[["self"],["containerdnat"]],["bool"]]],[11,"ne","","",28,[[["self"],["containerdnat"]],["bool"]]],[11,"eq","","",29,[[["self"],["containerdnatrule"]],["bool"]]],[11,"ne","","",29,[[["self"],["containerdnatrule"]],["bool"]]],[11,"fmt","dfw::errors","",0,[[["formatter"],["self"]],["result"]]],[11,"fmt","dfw::nftables","",3,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",4,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",5,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",6,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",7,[[["formatter"],["self"]],["result"]]],[11,"fmt","dfw::process","",9,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",8,[[["formatter"],["self"]],["result"]]],[11,"fmt","dfw::rule","",12,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",13,[[["formatter"],["self"]],["result"]]],[11,"fmt","dfw::types","",14,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",15,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",16,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",17,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",18,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",19,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",20,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",21,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",22,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",23,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",24,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",25,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",26,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",28,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",29,[[["formatter"],["self"]],["result"]]],[11,"fmt","dfw::errors","",0,[[["self"],["formatter"]],["result"]]],[11,"fmt","dfw::nftables","",3,[[["self"],["formatter"]],[["result",["error"]],["error"]]]],[11,"fmt","","",4,[[["self"],["formatter"]],[["result",["error"]],["error"]]]],[11,"fmt","","",5,[[["self"],["formatter"]],[["result",["error"]],["error"]]]],[11,"fmt","","",6,[[["self"],["formatter"]],[["result",["error"]],["error"]]]],[11,"fmt","","",7,[[["self"],["formatter"]],[["result",["error"]],["error"]]]],[11,"hash","","",6,[[["self"],["__h"]]]],[11,"hash","","",7,[[["self"],["__h"]]]],[11,"hash","dfw::types","",15,[[["self"],["__h"]]]],[11,"hash","","",16,[[["self"],["__h"]]]],[11,"hash","","",18,[[["self"],["__h"]]]],[11,"hash","","",19,[[["self"],["__h"]]]],[11,"hash","","",20,[[["self"],["__h"]]]],[11,"hash","","",21,[[["self"],["__h"]]]],[11,"hash","","",22,[[["self"],["__h"]]]],[11,"hash","","",23,[[["self"],["__h"]]]],[11,"hash","","",24,[[["self"],["__h"]]]],[11,"hash","","",25,[[["self"],["__h"]]]],[11,"hash","","",26,[[["self"],["__h"]]]],[11,"hash","","",28,[[["self"],["__h"]]]],[11,"hash","","",29,[[["self"],["__h"]]]],[11,"from_str","dfw::nftables","",6,[[["str"]],[["chainpolicy"],["result",["chainpolicy"]]]]],[11,"from_str","","",7,[[["str"]],[["ruleverdict"],["result",["ruleverdict"]]]]],[11,"from_str","dfw::types","Convert a formatted string into a `ExposePort`.",26,[[["str"]],["result"]]],[11,"name","dfw::errors","",0,[[["self"]],[["str"],["option",["str"]]]]],[11,"cause","","",0,[[["self"]],[["option",["fail"]],["fail"]]]],[11,"backtrace","","",0,[[["self"]],[["option",["backtrace"]],["backtrace"]]]],[11,"deserialize","dfw::nftables","",6,[[["__d"]],["result"]]],[11,"deserialize","","",7,[[["__d"]],["result"]]],[11,"deserialize","dfw::types","",14,[[["__d"]],["result"]]],[11,"deserialize","","",15,[[["__d"]],["result"]]],[11,"deserialize","","",16,[[["__d"]],["result"]]],[11,"deserialize","","",17,[[["__d"]],["result"]]],[11,"deserialize","","",18,[[["__d"]],["result"]]],[11,"deserialize","","",19,[[["__d"]],["result"]]],[11,"deserialize","","",20,[[["__d"]],["result"]]],[11,"deserialize","","",21,[[["__d"]],["result"]]],[11,"deserialize","","",22,[[["__d"]],["result"]]],[11,"deserialize","","",23,[[["__d"]],["result"]]],[11,"deserialize","","",24,[[["__d"]],["result"]]],[11,"deserialize","","",25,[[["__d"]],["result"]]],[11,"deserialize","","",26,[[["__d"]],["result"]]],[11,"deserialize","","",28,[[["__d"]],["result"]]],[11,"deserialize","","",29,[[["__d"]],["result"]]],[11,"serialize","dfw::nftables","",6,[[["serializer"],["key"],["record"],["self"]],["result"]]],[11,"serialize","","",7,[[["serializer"],["key"],["record"],["self"]],["result"]]]],"p":[[4,"DFWError"],[13,"NFTablesError"],[13,"TraitMethodUnimplemented"],[4,"Family"],[4,"Type"],[4,"Hook"],[4,"ChainPolicy"],[4,"RuleVerdict"],[3,"ProcessingOptions"],[4,"ContainerFilter"],[8,"Process"],[3,"ProcessContext"],[3,"Rule"],[3,"RuleBuilder"],[3,"DFW"],[3,"Defaults"],[3,"Table"],[3,"Initialization"],[3,"ContainerToContainer"],[3,"ContainerToContainerRule"],[3,"ContainerToWiderWorld"],[3,"ContainerToWiderWorldRule"],[3,"ContainerToHost"],[3,"ContainerToHostRule"],[3,"WiderWorldToContainer"],[3,"WiderWorldToContainerRule"],[3,"ExposePort"],[3,"ExposePortBuilder"],[3,"ContainerDNAT"],[3,"ContainerDNATRule"],[8,"FutureExt"]]};
addSearchOptions(searchIndex);initSearch(searchIndex);