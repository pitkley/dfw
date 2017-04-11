
#[derive(Deserialize, Debug)]
pub struct DFW {
    pub external_network_interface: Option<String>,
    pub initialization: Option<Initialization>,
    pub container_to_container: Option<ContainerToContainer>,
    pub container_to_wider_world: Option<ContainerToWiderWorld>,
    pub container_to_host: Option<ContainerToHost>,
}

#[derive(Deserialize, Debug)]
pub struct Initialization {
    pub filter: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
pub struct ContainerToContainer {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToContainerRule>>,
}

#[derive(Deserialize, Debug)]
pub struct ContainerToWiderWorld {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToWiderWorldRule>>,
}

#[derive(Deserialize, Debug)]
pub struct ContainerToHost {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToHostRule>>,
}

#[derive(Deserialize, Debug)]
pub struct ContainerToContainerRule {
    pub network: String,
    pub src_container: Option<String>,
    pub dst_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
}

#[derive(Deserialize, Debug)]
pub struct ContainerToWiderWorldRule {
    pub network: String,
    pub src_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
    pub external_network_interface: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
pub struct ContainerToHostRule {
    pub network: String,
    pub src_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
}
