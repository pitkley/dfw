use std::collections::HashMap as Map;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de::{self, Deserialize, Deserializer};

const DEFAULT_PROTOCOL: &'static str = "tcp";

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct DFW {
    pub defaults: Option<Defaults>,
    pub initialization: Option<Initialization>,
    pub container_to_container: Option<ContainerToContainer>,
    pub container_to_wider_world: Option<ContainerToWiderWorld>,
    pub container_to_host: Option<ContainerToHost>,
    pub wider_world_to_container: Option<WiderWorldToContainer>,
    pub container_dnat: Option<ContainerDNAT>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(default, deserialize_with = "option_string_or_vec")]
    pub external_network_interfaces: Option<Vec<String>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Initialization {
    pub v4: Option<Map<String, Vec<String>>>,
    pub v6: Option<Map<String, Vec<String>>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerToContainer {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToContainerRule>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerToContainerRule {
    pub network: String,
    pub src_container: Option<String>,
    pub dst_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerToWiderWorld {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToWiderWorldRule>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerToWiderWorldRule {
    pub network: Option<String>,
    pub src_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
    pub external_network_interface: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerToHost {
    pub default_policy: String,
    pub rules: Option<Vec<ContainerToHostRule>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerToHostRule {
    pub network: String,
    pub src_container: Option<String>,
    pub filter: Option<String>,
    pub action: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct WiderWorldToContainer {
    pub rules: Option<Vec<WiderWorldToContainerRule>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct WiderWorldToContainerRule {
    pub network: String,
    pub dst_container: String,
    #[serde(deserialize_with = "string_or_struct")]
    pub expose_port: ExposePort,
    pub external_network_interface: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default, Builder)]
#[serde(deny_unknown_fields)]
pub struct ExposePort {
    pub host_port: u16,
    #[builder(default="self.default_container_port()?")]
    pub container_port: Option<u16>,

    #[serde(default = "default_expose_port_family")]
    #[builder(default = "self.default_family()?")]
    pub family: String,
}

impl ExposePortBuilder {
    fn default_container_port(&self) -> Result<Option<u16>, String> {
        Ok(None)
    }

    fn default_family(&self) -> Result<String, String> {
        Ok(DEFAULT_PROTOCOL.to_owned())
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
                       .family(split[1].to_owned())
                       .build()
                       .unwrap()
               }
               _ => return Err(format!("port string has invalid format '{}'", s)),
           })
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerDNAT {
    pub rules: Option<Vec<ContainerDNATRule>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContainerDNATRule {
    pub src_network: Option<String>,
    pub src_container: Option<String>,
    pub dst_network: String,
    pub dst_container: String,
    #[serde(deserialize_with = "string_or_struct")]
    pub expose_port: ExposePort,
}

fn default_expose_port_family() -> String {
    DEFAULT_PROTOCOL.to_owned()
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

fn string_or_vec<D>(d: D) -> Result<Vec<String>, D::Error>
    where D: Deserializer
{
    struct StringOrVec(PhantomData<Vec<String>>);

    impl de::Visitor for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where E: de::Error
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
            where S: de::SeqVisitor
        {
            Deserialize::deserialize(de::value::SeqVisitorDeserializer::new(visitor))
        }
    }

    d.deserialize(StringOrVec(PhantomData))
}

fn option_string_or_vec<D>(d: D) -> Result<Option<Vec<String>>, D::Error>
    where D: Deserializer
{
    string_or_vec(d).map(Some)
}
