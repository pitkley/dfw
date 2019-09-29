// Copyright 2017 - 2019 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! This module abstracts various nftables concepts into native Rust types.

use serde::Deserialize;
use slog;
use strum_macros::{Display, EnumString};

/// Represenation of nftables table-families.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Family {
    /// IPv4 table family
    Ip,
    /// IPv6 table family
    Ip6,
    /// Dualstack IPv4/IPv6 table family
    Inet,
    /// ARP table family
    Arp,
    /// Bridge table family
    Bridge,
    /// Netdev table family
    Netdev,
}

/// Representation of nftables chain-types.
///
/// ## Attribution
///
/// Parts of the documentation have been taken from
/// <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains>.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Type {
    /// Is used to filter packets.
    ///
    /// Supported by the following table-families:
    ///
    /// * Arp
    /// * Bridge
    /// * Ip
    /// * Ip6
    /// * Inet
    Filter,
    /// Is used to reroute packets if any relevant IP header field or the packet mark is modified.
    ///
    /// Supported by the following table-families:
    ///
    /// * Ip
    /// * Ip6
    Route,
    /// Is used to perform Networking Address Translation (NAT).
    ///
    /// Supported by the following table-families:
    ///
    /// * Ip
    /// * Ip6
    Nat,
}

/// Representation of nftables chain hooks.
///
/// Order of hook execution:
///
/// * Ingress _(for netdev-family)_
/// * Prerouting
/// * Input
/// * Forward
/// * Output
/// * Postrouting
///
/// ## Attribution
///
/// Parts of the documentation have been taken from
/// <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains>.
#[derive(Debug, Clone, Copy, Display)]
#[strum(serialize_all = "snake_case")]
pub enum Hook {
    /// Ingress allows traffic-filtering before pre-routing, after the packet traversed the NIC.
    ///
    /// Only available for the netdev-family.
    Ingress,
    /// Prerouting allows traffic-filtering before the packets have been routed.
    Prerouting,
    /// Input allows traffic-filtering for packets that have been routed to the local system.
    Input,
    /// Forward allows traffic-filtering for packets that were not routed to the local system.
    Forward,
    /// Output allows traffic-filtering for packets leaving the local system.
    Output,
    /// Postrouting allows traffic-filtering for already routed packets leaving the local system.
    Postrouting,
}

/// Representation of nftables chain policies.
///
/// ## Attribution
///
/// Parts of the documentation have been taken from
/// <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains>.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "snake_case")]
pub enum ChainPolicy {
    /// The accept verdict means that the packet will keep traversing the network stack.
    #[strum(to_string = "accept", serialize = "accept", serialize = "ACCEPT")]
    #[serde(alias = "ACCEPT")]
    Accept,
    /// The drop verdict means that the packet is discarded if the packet reaches the end of the
    /// base chain.
    #[strum(to_string = "drop", serialize = "drop", serialize = "DROP")]
    #[serde(alias = "DROP")]
    Drop,
}

impl Default for ChainPolicy {
    fn default() -> ChainPolicy {
        ChainPolicy::Accept
    }
}

impl slog::Value for ChainPolicy {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        self.to_string().serialize(record, key, serializer)
    }
}

/// Representation of nftables rule policies.
///
/// ## Attribution
///
/// Parts of the documentation have been taken from
/// <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains>.
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Display, EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "snake_case")]
pub enum RuleVerdict {
    /// The accept verdict means that the packet will keep traversing the network stack.
    #[serde(alias = "ACCEPT")]
    #[strum(to_string = "accept", serialize = "accept", serialize = "ACCEPT")]
    Accept,
    /// The drop verdict means that the packet is discarded if the packet reaches the end of the
    /// base chain.
    #[serde(alias = "DROP")]
    #[strum(to_string = "drop", serialize = "drop", serialize = "DROP")]
    Drop,
    /// The reject verdict means that the packet is responded to with an ICMP message stating that
    /// it was rejected.
    #[serde(alias = "REJECT")]
    #[strum(to_string = "reject", serialize = "reject", serialize = "REJECT")]
    Reject,
}

impl Default for RuleVerdict {
    fn default() -> RuleVerdict {
        RuleVerdict::Accept
    }
}

impl slog::Value for RuleVerdict {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        self.to_string().serialize(record, key, serializer)
    }
}

/// Construct nft command for adding a table.
pub fn add_table(family: Family, table: &str) -> String {
    format!("add table {} {}", family, table)
}

/// Construct nft command for flushing a table.
pub fn flush_table(family: Family, table: &str) -> String {
    format!("flush table {} {}", family, table)
}

/// Construct nft command for deleting a table.
pub fn delete_table(family: Family, table: &str) -> String {
    format!("delete table {} {}", family, table)
}

/// Construct nft command for adding a base chain.
pub fn add_chain(family: Family, table: &str, chain: &str) -> String {
    format!("add chain {} {} {}", family, table, chain)
}

/// Construct nft command for adding a base chain.
pub fn add_base_chain(
    family: Family,
    table: &str,
    chain: &str,
    r#type: Type,
    hook: Hook,
    priority: i16,
) -> String {
    format!(
        "add chain {} {} {} {{ type {} hook {} priority {} ; }}",
        family, table, chain, r#type, hook, priority
    )
}

/// Construct nft command for setting the policy for a chain.
pub fn set_chain_policy(family: Family, table: &str, chain: &str, policy: ChainPolicy) -> String {
    format!(
        "add chain {} {} {} {{ policy {} ; }}",
        family, table, chain, policy
    )
}

/// Construct nft command for adding a rule to a chain.
pub fn add_rule(family: Family, table: &str, chain: &str, rule: &str) -> String {
    format!("add rule {} {} {} {}", family, table, chain, rule)
}

/// Construct nft command for inserting a rule into a chain.
pub fn insert_rule(
    family: Family,
    table: &str,
    chain: &str,
    rule: &str,
    position: Option<u32>,
) -> String {
    format!(
        "insert rule {} {} {} {}{}",
        family,
        table,
        chain,
        if let Some(position) = position {
            format!("position {} ", position)
        } else {
            "".to_owned()
        },
        rule
    )
}

#[cfg(test)]
mod test {
    use super::{ChainPolicy, RuleVerdict};
    use std::str::FromStr;

    #[test]
    fn chainpolicy_fromstr() {
        assert_eq!(ChainPolicy::Accept, FromStr::from_str("accept").unwrap());
        assert_eq!(ChainPolicy::Accept, FromStr::from_str("ACCEPT").unwrap());
        assert_eq!(ChainPolicy::Drop, FromStr::from_str("drop").unwrap());
        assert_eq!(ChainPolicy::Drop, FromStr::from_str("DROP").unwrap());
    }

    #[test]
    fn chainpolicy_tostring() {
        assert_eq!("accept", &ChainPolicy::Accept.to_string());
        assert_eq!("drop", &ChainPolicy::Drop.to_string());
    }

    #[test]
    fn RuleVerdict_fromstr() {
        assert_eq!(RuleVerdict::Accept, FromStr::from_str("accept").unwrap());
        assert_eq!(RuleVerdict::Accept, FromStr::from_str("ACCEPT").unwrap());
        assert_eq!(RuleVerdict::Drop, FromStr::from_str("drop").unwrap());
        assert_eq!(RuleVerdict::Drop, FromStr::from_str("DROP").unwrap());
        assert_eq!(RuleVerdict::Reject, FromStr::from_str("reject").unwrap());
        assert_eq!(RuleVerdict::Reject, FromStr::from_str("REJECT").unwrap());
    }

    #[test]
    fn RuleVerdict_tostring() {
        assert_eq!("accept", &RuleVerdict::Accept.to_string());
        assert_eq!("drop", &RuleVerdict::Drop.to_string());
        assert_eq!("reject", &RuleVerdict::Reject.to_string());
    }
}
