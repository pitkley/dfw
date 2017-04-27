// Copyright 2017 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

use std::collections::HashMap as Map;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use serde::de::{self, Deserialize, Deserializer, DeserializeSeed};

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
    #[serde(default, deserialize_with = "option_string_or_seq_string")]
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
    #[serde(deserialize_with = "single_or_seq_string_or_struct")]
    pub expose_port: Vec<ExposePort>,
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
    #[serde(deserialize_with = "single_or_seq_string_or_struct")]
    pub expose_port: Vec<ExposePort>,
}

fn default_expose_port_family() -> String {
    DEFAULT_PROTOCOL.to_owned()
}

struct StringOrStruct<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for StringOrStruct<T>
    where T: Deserialize<'de> + FromStr<Err = String>
{
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("integer, string or map")
    }

    fn visit_i64<E>(self, value: i64) -> Result<T, E>
        where E: de::Error
    {
        FromStr::from_str(&value.to_string()).map_err(de::Error::custom)
    }

    fn visit_str<E>(self, value: &str) -> Result<T, E>
        where E: de::Error
    {
        FromStr::from_str(value).map_err(de::Error::custom)
    }

    fn visit_map<M>(self, visitor: M) -> Result<T, M::Error>
        where M: de::MapAccess<'de>
    {
        Deserialize::deserialize(de::value::MapAccessDeserializer::new(visitor))
    }
}

// Thanks to @dtolnay for the support:
//   https://github.com/serde-rs/serde/issues/901#issuecomment-297070279
impl<'de, T> DeserializeSeed<'de> for StringOrStruct<T>
    where T: Deserialize<'de> + FromStr<Err = String>
{
    type Value = T;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where D: Deserializer<'de>
    {
        deserializer.deserialize_any(self)
    }
}

fn string_or_struct<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where T: Deserialize<'de> + FromStr<Err = String>,
          D: Deserializer<'de>
{
    deserializer.deserialize_any(StringOrStruct(PhantomData))
}

struct SingleOrSeqStringOrStruct<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for SingleOrSeqStringOrStruct<T>
    where T: Deserialize<'de> + FromStr<Err = String>
{
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("sequence of integers, strings or maps \
                             or a single integer, string or map")
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where E: de::Error
    {
        Ok(vec![FromStr::from_str(&value.to_string()).unwrap()])
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where E: de::Error
    {
        Ok(vec![FromStr::from_str(value).unwrap()])
    }

    fn visit_map<M>(self, visitor: M) -> Result<Self::Value, M::Error>
        where M: de::MapAccess<'de>
    {
        Deserialize::deserialize(de::value::MapAccessDeserializer::new(visitor)).map(|e| vec![e])
    }

    fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where S: de::SeqAccess<'de>
    {
        let mut vec = Vec::new();
        while let Some(element) = seq.next_element_seed(StringOrStruct(PhantomData))? {
            vec.push(element);
        }
        Ok(vec)
    }
}

fn single_or_seq_string_or_struct<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where T: Deserialize<'de> + FromStr<Err = String>,
          D: Deserializer<'de>
{
    deserializer.deserialize_any(SingleOrSeqStringOrStruct(PhantomData))
}

fn string_or_seq_string<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where D: Deserializer<'de>
{
    struct StringOrSeqString(PhantomData<Vec<String>>);

    impl<'de> de::Visitor<'de> for StringOrSeqString {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or sequence of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where E: de::Error
        {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
            where S: de::SeqAccess<'de>
        {
            Deserialize::deserialize(de::value::SeqAccessDeserializer::new(visitor))
        }
    }

    deserializer.deserialize_any(StringOrSeqString(PhantomData))
}

fn option_string_or_seq_string<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
    where D: Deserializer<'de>
{
    string_or_seq_string(deserializer).map(Some)
}
