use std::collections::HashMap as Map;

use boondock::container::Container;
use boondock::network::Network;

use errors::*;

pub fn get_container_map(containers: &Vec<Container>) -> Result<Option<Map<String, &Container>>> {
    let mut container_map: Map<String, &Container> = Map::new();
    for container in containers {
        for name in &container.Names {
            container_map.insert(name.clone().trim_left_matches("/").to_owned(), &container);
        }
    }

    if container_map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(container_map))
    }
}

pub fn get_network_map(networks: &Vec<Network>) -> Result<Option<Map<String, &Network>>> {
    let mut network_map: Map<String, &Network> = Map::new();
    for network in networks {
        network_map.insert(network.Name.clone(), &network);
    }

    if network_map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(network_map))
    }
}
