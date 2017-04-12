use std::collections::HashMap as Map;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de::{self, Deserialize, Deserializer};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct DFW {
    pub external_network_interface: Option<String>,
    pub initialization: Option<Initialization>,
    pub container_to_container: Option<ContainerToContainer>,
    pub container_to_wider_world: Option<ContainerToWiderWorld>,
    pub container_to_host: Option<ContainerToHost>,
    pub wider_world_to_container: Option<WiderWorldToContainer>,
    pub container_dnat: Option<ContainerDNAT>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Initialization {
    pub v4: Option<Map<String, Vec<String>>>,
    pub v6: Option<Map<String, Vec<String>>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerToContainer {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToContainerRule>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerToContainerRule {
    pub network: String,
    pub src_container: Option<String>,
    pub dst_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerToWiderWorld {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToWiderWorldRule>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerToWiderWorldRule {
    pub network: Option<String>,
    pub src_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
    pub external_network_interface: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerToHost {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToHostRule>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerToHostRule {
    pub network: String,
    pub src_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct WiderWorldToContainer {
    pub rules: Option<Vec<WiderWorldToContainerRule>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct WiderWorldToContainerRule {
    pub network: String,
    pub dst_container: String,
    #[serde(deserialize_with = "string_or_struct")]
    pub expose_port: ExposePort,
    pub external_network_interface: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Default, Builder)]
#[serde(deny_unknown_fields)]
pub struct ExposePort {
    pub host_port: u16,
    #[builder(default="self.default_container_port()?")]
    pub container_port: Option<u16>,

    // TODO: find better way to use same default for both deserializing and building
    // maybe just a constant?
    #[serde(default = "default_expose_port_family")]
    #[builder(default = "self.default_family()?")]
    pub family: String,
}

impl ExposePortBuilder {
    fn default_container_port(&self) -> Result<Option<u16>, String> {
        Ok(None)
    }

    fn default_family(&self) -> Result<String, String> {
        Ok("tcp".to_string())
    }
}

impl FromStr for ExposePort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split: Vec<&str> = s.split('/').collect();
        Ok(match split.len() {
               1 => {
                   ExposePortBuilder::default()
                       .host_port(split[0].parse().unwrap())
                       .build()
                       .unwrap()
               }
               2 => {
                   ExposePortBuilder::default()
                       .host_port(split[0].parse().unwrap())
                       .family(split[1].to_string())
                       .build()
                       .unwrap()
               }
               _ => return Err(format!("port string has invalid format '{}'", s)),
           })
    }
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerDNAT {
    pub rules: Option<Vec<ContainerDNATRules>>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ContainerDNATRules {
    pub src_network: Option<String>,
    pub src_container: Option<String>,
    pub dst_network: String,
    pub dst_container: String,
    #[serde(deserialize_with = "string_or_struct")]
    pub expose_port: ExposePort,
}

fn default_expose_port_family() -> String {
    "tcp".to_string()
}

fn string_or_struct<T, D>(d: D) -> Result<T, D::Error>
    where T: Deserialize + FromStr<Err = String>,
          D: Deserializer
{
    struct StringOrStruct<T>(PhantomData<T>);

    impl<T> de::Visitor for StringOrStruct<T>
        where T: Deserialize + FromStr<Err = String>
    {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("integer, string or map")
        }

        fn visit_i64<E>(self, value: i64) -> Result<T, E>
            where E: de::Error
        {
            Ok(FromStr::from_str(&value.to_string()).unwrap())
        }

        fn visit_str<E>(self, value: &str) -> Result<T, E>
            where E: de::Error
        {
            Ok(FromStr::from_str(value).unwrap())
        }

        fn visit_map<M>(self, visitor: M) -> Result<T, M::Error>
            where M: de::MapVisitor
        {
            Deserialize::deserialize(de::value::MapVisitorDeserializer::new(visitor))
        }
    }

    d.deserialize(StringOrStruct(PhantomData))
}
