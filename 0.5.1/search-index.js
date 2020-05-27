var searchIndex={};
searchIndex["dfw"] = {"doc":"DFW - Docker Firewall Framework in Rust","i":[[0,"errors","dfw","Errors, using [`failure`][failure].",null,null],[4,"DFWError","dfw::errors","",null,null],[13,"TraitMethodUnimplemented","","",0,null],[12,"method","dfw::errors::DFWError","",1,null],[6,"Result","dfw::errors","",null,null],[0,"iptables","dfw","This module holds the `IPTables` compatibility trait,…",null,null],[3,"IPTablesRestore","dfw::iptables","`IPTables` implementation which tracks the functions…",null,null],[3,"IPTablesDummy","","`IPTables` implementation which does not interact with the…",null,null],[3,"IPTablesLogger","","`IPTables` implementation which does not interact with the…",null,null],[4,"IPVersion","","Enum identifying a IP protocol version. Can be used by…",null,null],[13,"IPv4","","IP protocol version 4",2,null],[13,"IPv6","","IP protocol version 6",2,null],[8,"IPTables","","Compatibility trait to generalize the API used by…",null,null],[10,"get_policy","","Get the default policy for a table/chain.",3,[[["str"],["self"]],[["result",["string"]],["string"]]]],[10,"set_policy","","Set the default policy for a table/chain.",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"execute","","Executes a given `command` on the chain. Returns the…",3,[[["str"],["self"]],[["result",["output"]],["output"]]]],[10,"exists","","Checks for the existence of the `rule` in the table/chain.…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"chain_exists","","Checks for the existence of the `chain` in the table.…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"insert","","Inserts `rule` in the `position` to the table/chain.…",3,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[10,"insert_unique","","Inserts `rule` in the `position` to the table/chain if it…",3,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[10,"replace","","Replaces `rule` in the `position` to the table/chain.…",3,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[10,"append","","Appends `rule` to the table/chain. Returns `true` if the…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"append_unique","","Appends `rule` to the table/chain if it does not exist.…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"append_replace","","Appends or replaces `rule` to the table/chain if it does…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"delete","","Deletes `rule` from the table/chain. Returns `true` if the…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"delete_all","","Deletes all repetition of the `rule` from the table/chain.…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"list","","Lists rules in the table/chain.",3,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[10,"list_table","","Lists rules in the table.",3,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[10,"list_chains","","Lists the name of each chain in the table.",3,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[10,"new_chain","","Creates a new user-defined chain. Returns `true` if the…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"flush_chain","","Flushes (deletes all rules) a chain. Returns `true` if the…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"rename_chain","","Renames a chain in the table. Returns `true` if the chain…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"delete_chain","","Deletes a user-defined chain in the table. Returns `true`…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"flush_table","","Flushes all chains in a table. Returns `true` if the…",3,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[10,"commit","","Commit the changes queued. Only has an effect on some…",3,[[["self"]],[["result",["bool"]],["bool"]]]],[11,"new","","Create a new instance of `IPTablesRestore`",4,[[["ipversion"]],[["result",["iptablesrestore"]],["iptablesrestore"]]]],[11,"get_rules","","Retrieve the current text that would be passed to…",4,[[["self"]],[["vec",["string"]],["string"]]]],[11,"new","","Create a new instance of `IPTablesLogger`",5,[[],["iptableslogger"]]],[11,"logs","","Get the collected logs.",5,[[["self"]],["vec"]]],[0,"process","dfw","This module holds the types related to configuration…",null,null],[3,"ProcessDFW","dfw::process","Enclosing struct to manage rule processing.",null,null],[3,"ProcessingOptions","","Options to configure the processing procedure.",null,null],[12,"container_filter","","Option to filter the containers to be processed, see…",6,null],[4,"ContainerFilter","","Option to filter the containers to be processed",null,null],[13,"All","","Process all containers, i.e. don't filter.",7,null],[13,"Running","","Only process running containers.",7,null],[11,"new","","Create a new instance of `ProcessDFW` for rule processing.",8,[[["iptables"],["dfw"],["docker"],["processingoptions"],["logger"]],[["result",["processdfw"]],["processdfw"]]]],[11,"process","","Start the processing using the configuration given at…",8,[[["self"]],["result"]]],[0,"types","dfw","The types in this module make up the structure of the…",null,null],[3,"DFW","dfw::types","`DFW` is the parent type defining the complete…",null,null],[12,"defaults","","The `defaults` configuration section",9,null],[12,"initialization","","The `initialization` configuration section",9,null],[12,"container_to_container","","The `container_to_container` configuration section",9,null],[12,"container_to_wider_world","","The `container_to_wider_world` configuration section",9,null],[12,"container_to_host","","The `container_to_host` configuration section",9,null],[12,"wider_world_to_container","","The `wider_world_to_container` configuration section",9,null],[12,"container_dnat","","The `container_dnat` configuration section",9,null],[3,"Defaults","","The default configuration section, used by DFW for rule…",null,null],[12,"external_network_interfaces","","This defines the external network interfaces of the host…",10,null],[3,"Initialization","","The initialization section allows you to add custom rules…",null,null],[12,"v4","","Initialization rules for iptables (IPv4). Expects a map…",11,null],[12,"v6","","Initialization rules for ip6tables (IPv6). Expects a map…",11,null],[3,"ContainerToContainer","","The container-to-container section, defining how…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",12,null],[12,"rules","","An optional list of rules, see `ContainerToContainerRule`.",12,null],[3,"ContainerToContainerRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Common network between the source container and the…",13,null],[12,"src_container","","Source container to apply the rule to.",13,null],[12,"dst_container","","Destination container to apply the rule to.",13,null],[12,"filter","","Additional filter, which will be added to the iptables…",13,null],[12,"action","","Action to take (i.e. `ACCEPT`, `DROP`, `REFUSE`).",13,null],[3,"ContainerToWiderWorld","","The container-to-wider-world section, defining how…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",14,null],[12,"rules","","An optional list of rules, see `ContainerToWiderWorldRule`.",14,null],[3,"ContainerToWiderWorldRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Network of the source container to apply the rule to.",15,null],[12,"src_container","","Source container to apply the rule to.",15,null],[12,"filter","","Additional filter, which will be added to the iptables…",15,null],[12,"action","","Action to take (i.e. `ACCEPT`, `DROP`, `REFUSE`).",15,null],[12,"external_network_interface","","Specific external network interface to target.",15,null],[3,"ContainerToHost","","The container-to-host section, defining how containers can…",null,null],[12,"default_policy","","The `default_policy` defines the default for when there is…",16,null],[12,"rules","","An optional list of rules, see `ContainerToHostRule`.",16,null],[3,"ContainerToHostRule","","Definition for a rule to be used in the container-to-host…",null,null],[12,"network","","Network of the source container to apply the rule to.",17,null],[12,"src_container","","Source container to apply the rule to.",17,null],[12,"filter","","Additional filter, which will be added to the iptables…",17,null],[12,"action","","Action to take (i.e. `ACCEPT`, `DROP`, `REFUSE`).",17,null],[3,"WiderWorldToContainer","","The wider-world-to-container section, defining how…",null,null],[12,"rules","","An optional list of rules, see `WiderWorldToContainerRule`.",18,null],[3,"WiderWorldToContainerRule","","Definition for a rule to be used in the…",null,null],[12,"network","","Network of the destination container to apply the rule to.",19,null],[12,"dst_container","","Destination container to apply the rule to.",19,null],[12,"expose_port","","Ports to apply the rule to.",19,null],[12,"external_network_interface","","Specific external network interface to target.",19,null],[12,"source_cidr","","Source CIDRs to which incoming traffic should be restricted.",19,null],[3,"ExposePort","","Struct to hold a port definition to expose on the…",null,null],[12,"host_port","","Port the `container_port` should be exposed to on the host.",20,null],[12,"container_port","","Port the `host_port` should map to into the container.",20,null],[12,"family","","Family of the exposed port.",20,null],[3,"ExposePortBuilder","","Builder for `ExposePort`.",null,null],[12,"host_port","","Port the `container_port` should be exposed to on the host.",21,null],[12,"container_port","","Port the `host_port` should map to into the container.",21,null],[12,"family","","Family of the exposed port.",21,null],[3,"ContainerDNAT","","The container-DNAT section, defining how containers can…",null,null],[12,"rules","","An optional list of rules, see `ContainerDNATRule`.",22,null],[3,"ContainerDNATRule","","Definition for a rule to be used in the container-DNAT…",null,null],[12,"src_network","","Network of the source container to apply the rule to.",23,null],[12,"src_container","","Source container to apply the rule to.",23,null],[12,"dst_network","","Network of the destination container to apply the rule to.",23,null],[12,"dst_container","","Destination container to apply the rule to.",23,null],[12,"expose_port","","Ports to apply the rule to.",23,null],[11,"host_port","","Port the `container_port` should be exposed to on the host.",21,[[["u16"],["self"]],["self"]]],[11,"container_port","","Port the `host_port` should map to into the container.",21,[[["option",["u16"]],["self"],["u16"]],["self"]]],[11,"family","","Family of the exposed port.",21,[[["self"],["string"]],["self"]]],[11,"build","","Builds a new `ExposePort`.",21,[[["self"]],[["string"],["result",["exposeport","string"]],["exposeport"]]]],[0,"util","dfw","Utilities module",null,null],[5,"load_file","dfw::util","Load single TOML-file from path and deserialize it into…",null,[[["str"]],["result"]]],[5,"load_path","","Load all TOML-files from a path, concatenate their…",null,[[["str"]],["result"]]],[11,"from","dfw::errors","",0,[[["t"]],["t"]]],[11,"into","","",0,[[],["u"]]],[11,"to_string","","",0,[[["self"]],["string"]]],[11,"try_from","","",0,[[["u"]],["result"]]],[11,"try_into","","",0,[[],["result"]]],[11,"borrow","","",0,[[["self"]],["t"]]],[11,"borrow_mut","","",0,[[["self"]],["t"]]],[11,"type_id","","",0,[[["self"]],["typeid"]]],[11,"as_fail","","",0,[[["self"]],["fail"]]],[11,"from","dfw::iptables","",4,[[["t"]],["t"]]],[11,"into","","",4,[[],["u"]]],[11,"try_from","","",4,[[["u"]],["result"]]],[11,"try_into","","",4,[[],["result"]]],[11,"borrow","","",4,[[["self"]],["t"]]],[11,"borrow_mut","","",4,[[["self"]],["t"]]],[11,"type_id","","",4,[[["self"]],["typeid"]]],[11,"from","","",24,[[["t"]],["t"]]],[11,"into","","",24,[[],["u"]]],[11,"try_from","","",24,[[["u"]],["result"]]],[11,"try_into","","",24,[[],["result"]]],[11,"borrow","","",24,[[["self"]],["t"]]],[11,"borrow_mut","","",24,[[["self"]],["t"]]],[11,"type_id","","",24,[[["self"]],["typeid"]]],[11,"from","","",5,[[["t"]],["t"]]],[11,"into","","",5,[[],["u"]]],[11,"try_from","","",5,[[["u"]],["result"]]],[11,"try_into","","",5,[[],["result"]]],[11,"borrow","","",5,[[["self"]],["t"]]],[11,"borrow_mut","","",5,[[["self"]],["t"]]],[11,"type_id","","",5,[[["self"]],["typeid"]]],[11,"from","","",2,[[["t"]],["t"]]],[11,"into","","",2,[[],["u"]]],[11,"to_owned","","",2,[[["self"]],["t"]]],[11,"clone_into","","",2,[[["self"],["t"]]]],[11,"try_from","","",2,[[["u"]],["result"]]],[11,"try_into","","",2,[[],["result"]]],[11,"borrow","","",2,[[["self"]],["t"]]],[11,"borrow_mut","","",2,[[["self"]],["t"]]],[11,"type_id","","",2,[[["self"]],["typeid"]]],[11,"from","dfw::process","",8,[[["t"]],["t"]]],[11,"into","","",8,[[],["u"]]],[11,"try_from","","",8,[[["u"]],["result"]]],[11,"try_into","","",8,[[],["result"]]],[11,"borrow","","",8,[[["self"]],["t"]]],[11,"borrow_mut","","",8,[[["self"]],["t"]]],[11,"type_id","","",8,[[["self"]],["typeid"]]],[11,"from","","",6,[[["t"]],["t"]]],[11,"into","","",6,[[],["u"]]],[11,"to_owned","","",6,[[["self"]],["t"]]],[11,"clone_into","","",6,[[["self"],["t"]]]],[11,"try_from","","",6,[[["u"]],["result"]]],[11,"try_into","","",6,[[],["result"]]],[11,"borrow","","",6,[[["self"]],["t"]]],[11,"borrow_mut","","",6,[[["self"]],["t"]]],[11,"type_id","","",6,[[["self"]],["typeid"]]],[11,"from","","",7,[[["t"]],["t"]]],[11,"into","","",7,[[],["u"]]],[11,"to_owned","","",7,[[["self"]],["t"]]],[11,"clone_into","","",7,[[["self"],["t"]]]],[11,"try_from","","",7,[[["u"]],["result"]]],[11,"try_into","","",7,[[],["result"]]],[11,"borrow","","",7,[[["self"]],["t"]]],[11,"borrow_mut","","",7,[[["self"]],["t"]]],[11,"type_id","","",7,[[["self"]],["typeid"]]],[11,"from","dfw::types","",9,[[["t"]],["t"]]],[11,"into","","",9,[[],["u"]]],[11,"to_owned","","",9,[[["self"]],["t"]]],[11,"clone_into","","",9,[[["self"],["t"]]]],[11,"try_from","","",9,[[["u"]],["result"]]],[11,"try_into","","",9,[[],["result"]]],[11,"borrow","","",9,[[["self"]],["t"]]],[11,"borrow_mut","","",9,[[["self"]],["t"]]],[11,"type_id","","",9,[[["self"]],["typeid"]]],[11,"from","","",10,[[["t"]],["t"]]],[11,"into","","",10,[[],["u"]]],[11,"to_owned","","",10,[[["self"]],["t"]]],[11,"clone_into","","",10,[[["self"],["t"]]]],[11,"try_from","","",10,[[["u"]],["result"]]],[11,"try_into","","",10,[[],["result"]]],[11,"borrow","","",10,[[["self"]],["t"]]],[11,"borrow_mut","","",10,[[["self"]],["t"]]],[11,"type_id","","",10,[[["self"]],["typeid"]]],[11,"from","","",11,[[["t"]],["t"]]],[11,"into","","",11,[[],["u"]]],[11,"to_owned","","",11,[[["self"]],["t"]]],[11,"clone_into","","",11,[[["self"],["t"]]]],[11,"try_from","","",11,[[["u"]],["result"]]],[11,"try_into","","",11,[[],["result"]]],[11,"borrow","","",11,[[["self"]],["t"]]],[11,"borrow_mut","","",11,[[["self"]],["t"]]],[11,"type_id","","",11,[[["self"]],["typeid"]]],[11,"from","","",12,[[["t"]],["t"]]],[11,"into","","",12,[[],["u"]]],[11,"to_owned","","",12,[[["self"]],["t"]]],[11,"clone_into","","",12,[[["self"],["t"]]]],[11,"try_from","","",12,[[["u"]],["result"]]],[11,"try_into","","",12,[[],["result"]]],[11,"borrow","","",12,[[["self"]],["t"]]],[11,"borrow_mut","","",12,[[["self"]],["t"]]],[11,"type_id","","",12,[[["self"]],["typeid"]]],[11,"from","","",13,[[["t"]],["t"]]],[11,"into","","",13,[[],["u"]]],[11,"to_owned","","",13,[[["self"]],["t"]]],[11,"clone_into","","",13,[[["self"],["t"]]]],[11,"try_from","","",13,[[["u"]],["result"]]],[11,"try_into","","",13,[[],["result"]]],[11,"borrow","","",13,[[["self"]],["t"]]],[11,"borrow_mut","","",13,[[["self"]],["t"]]],[11,"type_id","","",13,[[["self"]],["typeid"]]],[11,"from","","",14,[[["t"]],["t"]]],[11,"into","","",14,[[],["u"]]],[11,"to_owned","","",14,[[["self"]],["t"]]],[11,"clone_into","","",14,[[["self"],["t"]]]],[11,"try_from","","",14,[[["u"]],["result"]]],[11,"try_into","","",14,[[],["result"]]],[11,"borrow","","",14,[[["self"]],["t"]]],[11,"borrow_mut","","",14,[[["self"]],["t"]]],[11,"type_id","","",14,[[["self"]],["typeid"]]],[11,"from","","",15,[[["t"]],["t"]]],[11,"into","","",15,[[],["u"]]],[11,"to_owned","","",15,[[["self"]],["t"]]],[11,"clone_into","","",15,[[["self"],["t"]]]],[11,"try_from","","",15,[[["u"]],["result"]]],[11,"try_into","","",15,[[],["result"]]],[11,"borrow","","",15,[[["self"]],["t"]]],[11,"borrow_mut","","",15,[[["self"]],["t"]]],[11,"type_id","","",15,[[["self"]],["typeid"]]],[11,"from","","",16,[[["t"]],["t"]]],[11,"into","","",16,[[],["u"]]],[11,"to_owned","","",16,[[["self"]],["t"]]],[11,"clone_into","","",16,[[["self"],["t"]]]],[11,"try_from","","",16,[[["u"]],["result"]]],[11,"try_into","","",16,[[],["result"]]],[11,"borrow","","",16,[[["self"]],["t"]]],[11,"borrow_mut","","",16,[[["self"]],["t"]]],[11,"type_id","","",16,[[["self"]],["typeid"]]],[11,"from","","",17,[[["t"]],["t"]]],[11,"into","","",17,[[],["u"]]],[11,"to_owned","","",17,[[["self"]],["t"]]],[11,"clone_into","","",17,[[["self"],["t"]]]],[11,"try_from","","",17,[[["u"]],["result"]]],[11,"try_into","","",17,[[],["result"]]],[11,"borrow","","",17,[[["self"]],["t"]]],[11,"borrow_mut","","",17,[[["self"]],["t"]]],[11,"type_id","","",17,[[["self"]],["typeid"]]],[11,"from","","",18,[[["t"]],["t"]]],[11,"into","","",18,[[],["u"]]],[11,"to_owned","","",18,[[["self"]],["t"]]],[11,"clone_into","","",18,[[["self"],["t"]]]],[11,"try_from","","",18,[[["u"]],["result"]]],[11,"try_into","","",18,[[],["result"]]],[11,"borrow","","",18,[[["self"]],["t"]]],[11,"borrow_mut","","",18,[[["self"]],["t"]]],[11,"type_id","","",18,[[["self"]],["typeid"]]],[11,"from","","",19,[[["t"]],["t"]]],[11,"into","","",19,[[],["u"]]],[11,"to_owned","","",19,[[["self"]],["t"]]],[11,"clone_into","","",19,[[["self"],["t"]]]],[11,"try_from","","",19,[[["u"]],["result"]]],[11,"try_into","","",19,[[],["result"]]],[11,"borrow","","",19,[[["self"]],["t"]]],[11,"borrow_mut","","",19,[[["self"]],["t"]]],[11,"type_id","","",19,[[["self"]],["typeid"]]],[11,"from","","",20,[[["t"]],["t"]]],[11,"into","","",20,[[],["u"]]],[11,"to_owned","","",20,[[["self"]],["t"]]],[11,"clone_into","","",20,[[["self"],["t"]]]],[11,"try_from","","",20,[[["u"]],["result"]]],[11,"try_into","","",20,[[],["result"]]],[11,"borrow","","",20,[[["self"]],["t"]]],[11,"borrow_mut","","",20,[[["self"]],["t"]]],[11,"type_id","","",20,[[["self"]],["typeid"]]],[11,"from","","",21,[[["t"]],["t"]]],[11,"into","","",21,[[],["u"]]],[11,"to_owned","","",21,[[["self"]],["t"]]],[11,"clone_into","","",21,[[["self"],["t"]]]],[11,"try_from","","",21,[[["u"]],["result"]]],[11,"try_into","","",21,[[],["result"]]],[11,"borrow","","",21,[[["self"]],["t"]]],[11,"borrow_mut","","",21,[[["self"]],["t"]]],[11,"type_id","","",21,[[["self"]],["typeid"]]],[11,"from","","",22,[[["t"]],["t"]]],[11,"into","","",22,[[],["u"]]],[11,"to_owned","","",22,[[["self"]],["t"]]],[11,"clone_into","","",22,[[["self"],["t"]]]],[11,"try_from","","",22,[[["u"]],["result"]]],[11,"try_into","","",22,[[],["result"]]],[11,"borrow","","",22,[[["self"]],["t"]]],[11,"borrow_mut","","",22,[[["self"]],["t"]]],[11,"type_id","","",22,[[["self"]],["typeid"]]],[11,"from","","",23,[[["t"]],["t"]]],[11,"into","","",23,[[],["u"]]],[11,"to_owned","","",23,[[["self"]],["t"]]],[11,"clone_into","","",23,[[["self"],["t"]]]],[11,"try_from","","",23,[[["u"]],["result"]]],[11,"try_into","","",23,[[],["result"]]],[11,"borrow","","",23,[[["self"]],["t"]]],[11,"borrow_mut","","",23,[[["self"]],["t"]]],[11,"type_id","","",23,[[["self"]],["typeid"]]],[11,"append","dfw::iptables","",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"delete","","",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"flush_chain","","",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"flush_table","","",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"set_policy","","",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"execute","","",4,[[["str"],["self"]],[["result",["output"]],["output"]]]],[11,"append_replace","","",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"list","","",4,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"list_table","","",4,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"list_chains","","",4,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"new_chain","","",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"commit","","",4,[[["self"]],[["result",["bool"]],["bool"]]]],[11,"insert","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"insert_unique","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"append_unique","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"get_policy","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"]],[["result",["string"]],["string"]]]],[11,"exists","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"chain_exists","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"replace","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"delete_all","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"rename_chain","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"delete_chain","","METHOD UNSUPPORTED IN `IPTablesRestore`!",4,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"get_policy","","",24,[[["str"],["self"]],[["result",["string"]],["string"]]]],[11,"set_policy","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"exists","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"chain_exists","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"insert","","",24,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"insert_unique","","",24,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"replace","","",24,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"append","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"append_unique","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"append_replace","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"delete","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"delete_all","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"list","","",24,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"list_table","","",24,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"list_chains","","",24,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"new_chain","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"flush_chain","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"rename_chain","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"delete_chain","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"flush_table","","",24,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"commit","","",24,[[["self"]],[["result",["bool"]],["bool"]]]],[11,"execute","","",24,[[["str"],["self"]],[["result",["output"]],["output"]]]],[11,"get_policy","","",5,[[["str"],["self"]],[["result",["string"]],["string"]]]],[11,"set_policy","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"exists","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"chain_exists","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"insert","","",5,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"insert_unique","","",5,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"replace","","",5,[[["str"],["self"],["i32"]],[["result",["bool"]],["bool"]]]],[11,"append","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"append_unique","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"append_replace","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"delete","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"delete_all","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"list","","",5,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"list_table","","",5,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"list_chains","","",5,[[["str"],["self"]],[["result",["vec"]],["vec",["string"]]]]],[11,"new_chain","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"flush_chain","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"rename_chain","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"delete_chain","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"flush_table","","",5,[[["str"],["self"]],[["result",["bool"]],["bool"]]]],[11,"commit","","",5,[[["self"]],[["result",["bool"]],["bool"]]]],[11,"execute","","",5,[[["str"],["self"]],[["result",["output"]],["output"]]]],[11,"clone","","",2,[[["self"]],["ipversion"]]],[11,"clone","dfw::process","",7,[[["self"]],["containerfilter"]]],[11,"clone","","",6,[[["self"]],["processingoptions"]]],[11,"clone","dfw::types","",9,[[["self"]],["dfw"]]],[11,"clone","","",10,[[["self"]],["defaults"]]],[11,"clone","","",11,[[["self"]],["initialization"]]],[11,"clone","","",12,[[["self"]],["containertocontainer"]]],[11,"clone","","",13,[[["self"]],["containertocontainerrule"]]],[11,"clone","","",14,[[["self"]],["containertowiderworld"]]],[11,"clone","","",15,[[["self"]],["containertowiderworldrule"]]],[11,"clone","","",16,[[["self"]],["containertohost"]]],[11,"clone","","",17,[[["self"]],["containertohostrule"]]],[11,"clone","","",18,[[["self"]],["widerworldtocontainer"]]],[11,"clone","","",19,[[["self"]],["widerworldtocontainerrule"]]],[11,"clone","","",20,[[["self"]],["exposeport"]]],[11,"clone","","",21,[[["self"]],["exposeportbuilder"]]],[11,"clone","","",22,[[["self"]],["containerdnat"]]],[11,"clone","","",23,[[["self"]],["containerdnatrule"]]],[11,"default","dfw::iptables","",5,[[],["iptableslogger"]]],[11,"default","dfw::process","",6,[[],["self"]]],[11,"default","dfw::types","",20,[[],["exposeport"]]],[11,"default","","",21,[[],["exposeportbuilder"]]],[11,"eq","dfw::process","",7,[[["self"],["containerfilter"]],["bool"]]],[11,"eq","","",6,[[["processingoptions"],["self"]],["bool"]]],[11,"ne","","",6,[[["processingoptions"],["self"]],["bool"]]],[11,"eq","dfw::types","",9,[[["dfw"],["self"]],["bool"]]],[11,"ne","","",9,[[["dfw"],["self"]],["bool"]]],[11,"eq","","",10,[[["defaults"],["self"]],["bool"]]],[11,"ne","","",10,[[["defaults"],["self"]],["bool"]]],[11,"eq","","",11,[[["self"],["initialization"]],["bool"]]],[11,"ne","","",11,[[["self"],["initialization"]],["bool"]]],[11,"eq","","",12,[[["self"],["containertocontainer"]],["bool"]]],[11,"ne","","",12,[[["self"],["containertocontainer"]],["bool"]]],[11,"eq","","",13,[[["self"],["containertocontainerrule"]],["bool"]]],[11,"ne","","",13,[[["self"],["containertocontainerrule"]],["bool"]]],[11,"eq","","",14,[[["self"],["containertowiderworld"]],["bool"]]],[11,"ne","","",14,[[["self"],["containertowiderworld"]],["bool"]]],[11,"eq","","",15,[[["self"],["containertowiderworldrule"]],["bool"]]],[11,"ne","","",15,[[["self"],["containertowiderworldrule"]],["bool"]]],[11,"eq","","",16,[[["containertohost"],["self"]],["bool"]]],[11,"ne","","",16,[[["containertohost"],["self"]],["bool"]]],[11,"eq","","",17,[[["containertohostrule"],["self"]],["bool"]]],[11,"ne","","",17,[[["containertohostrule"],["self"]],["bool"]]],[11,"eq","","",18,[[["self"],["widerworldtocontainer"]],["bool"]]],[11,"ne","","",18,[[["self"],["widerworldtocontainer"]],["bool"]]],[11,"eq","","",19,[[["widerworldtocontainerrule"],["self"]],["bool"]]],[11,"ne","","",19,[[["widerworldtocontainerrule"],["self"]],["bool"]]],[11,"eq","","",20,[[["exposeport"],["self"]],["bool"]]],[11,"ne","","",20,[[["exposeport"],["self"]],["bool"]]],[11,"eq","","",22,[[["containerdnat"],["self"]],["bool"]]],[11,"ne","","",22,[[["containerdnat"],["self"]],["bool"]]],[11,"eq","","",23,[[["self"],["containerdnatrule"]],["bool"]]],[11,"ne","","",23,[[["self"],["containerdnatrule"]],["bool"]]],[11,"fmt","dfw::errors","",0,[[["formatter"],["self"]],["result"]]],[11,"fmt","dfw::process","",7,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",6,[[["formatter"],["self"]],["result"]]],[11,"fmt","dfw::types","",9,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",10,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",11,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",12,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",13,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",14,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",15,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",16,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",17,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",18,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",19,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",20,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",22,[[["formatter"],["self"]],["result"]]],[11,"fmt","","",23,[[["formatter"],["self"]],["result"]]],[11,"fmt","dfw::errors","",0,[[["self"],["formatter"]],["result"]]],[11,"hash","dfw::types","",10,[[["self"],["__h"]]]],[11,"hash","","",12,[[["self"],["__h"]]]],[11,"hash","","",13,[[["self"],["__h"]]]],[11,"hash","","",14,[[["self"],["__h"]]]],[11,"hash","","",15,[[["self"],["__h"]]]],[11,"hash","","",16,[[["self"],["__h"]]]],[11,"hash","","",17,[[["self"],["__h"]]]],[11,"hash","","",18,[[["self"],["__h"]]]],[11,"hash","","",19,[[["self"],["__h"]]]],[11,"hash","","",20,[[["self"],["__h"]]]],[11,"hash","","",22,[[["self"],["__h"]]]],[11,"hash","","",23,[[["self"],["__h"]]]],[11,"from_str","","Convert a formatted string into a `ExposePort`.",20,[[["str"]],["result"]]],[11,"name","dfw::errors","",0,[[["self"]],[["str"],["option",["str"]]]]],[11,"cause","","",0,[[["self"]],[["option",["fail"]],["fail"]]]],[11,"backtrace","","",0,[[["self"]],[["option",["backtrace"]],["backtrace"]]]],[11,"deserialize","dfw::types","",9,[[["__d"]],["result"]]],[11,"deserialize","","",10,[[["__d"]],["result"]]],[11,"deserialize","","",11,[[["__d"]],["result"]]],[11,"deserialize","","",12,[[["__d"]],["result"]]],[11,"deserialize","","",13,[[["__d"]],["result"]]],[11,"deserialize","","",14,[[["__d"]],["result"]]],[11,"deserialize","","",15,[[["__d"]],["result"]]],[11,"deserialize","","",16,[[["__d"]],["result"]]],[11,"deserialize","","",17,[[["__d"]],["result"]]],[11,"deserialize","","",18,[[["__d"]],["result"]]],[11,"deserialize","","",19,[[["__d"]],["result"]]],[11,"deserialize","","",20,[[["__d"]],["result"]]],[11,"deserialize","","",22,[[["__d"]],["result"]]],[11,"deserialize","","",23,[[["__d"]],["result"]]]],"p":[[4,"DFWError"],[13,"TraitMethodUnimplemented"],[4,"IPVersion"],[8,"IPTables"],[3,"IPTablesRestore"],[3,"IPTablesLogger"],[3,"ProcessingOptions"],[4,"ContainerFilter"],[3,"ProcessDFW"],[3,"DFW"],[3,"Defaults"],[3,"Initialization"],[3,"ContainerToContainer"],[3,"ContainerToContainerRule"],[3,"ContainerToWiderWorld"],[3,"ContainerToWiderWorldRule"],[3,"ContainerToHost"],[3,"ContainerToHostRule"],[3,"WiderWorldToContainer"],[3,"WiderWorldToContainerRule"],[3,"ExposePort"],[3,"ExposePortBuilder"],[3,"ContainerDNAT"],[3,"ContainerDNATRule"],[3,"IPTablesDummy"]]};
addSearchOptions(searchIndex);initSearch(searchIndex);