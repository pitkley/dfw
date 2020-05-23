// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! This module implements the nftables backend for DFW.

use crate::errors::*;
use crate::{FirewallBackend, ProcessContext};
use slog::{debug, info, o, trace};
use std::io::prelude::*;
use std::io::BufWriter;
use std::process::Command;
use strum_macros::Display;

mod process;
mod rule;
pub mod types;

const NF_IP_PRI_NAT_DST: i16 = -100;
const NF_IP_PRI_FILTER: i16 = 0;
const NF_IP_PRI_NAT_SRC: i16 = 100;

const NF_PRIORITY_IP_NAT_PREROUTING_DFW: i16 = NF_IP_PRI_NAT_DST - 5;
const NF_PRIORITY_IP6_NAT_PREROUTING_DFW: i16 = NF_IP_PRI_NAT_DST - 5;
const NF_PRIORITY_INET_FILTER_ANY_DFW: i16 = NF_IP_PRI_FILTER - 5;
const NF_PRIORITY_IP_NAT_POSTROUTING_DFW: i16 = NF_IP_PRI_NAT_SRC - 5;
const NF_PRIORITY_IP6_NAT_POSTROUTING_DFW: i16 = NF_IP_PRI_NAT_SRC - 5;

const DFW_MARK: &str = "0xdf";

/// Marker struct to implement nftables as a firewall backend.
#[derive(Debug)]
pub struct Nftables;
impl FirewallBackend for Nftables {
    type Rule = String;
    type Defaults = types::Defaults;

    fn apply(rules: Vec<Self::Rule>, ctx: &ProcessContext<Nftables>) -> Result<()> {
        if ctx.dry_run {
            info!(ctx.logger, "Performing dry-run, will not update any rules");
        } else {
            // To atomically update the ruleset, we need to write a file and pass that to `nft -f`.
            let rule_file = tempfile::Builder::new().tempfile()?;
            let rule_file_path = rule_file.as_ref().as_os_str().to_os_string();
            debug!(ctx.logger, "Writing rules to temporary file";
                   o!("file_path" => rule_file_path.to_string_lossy().into_owned()));
            let mut writer = BufWriter::new(rule_file);

            for rule in rules {
                writeln!(writer, "{}", rule)?;
            }
            writer.flush()?;
            trace!(ctx.logger, "Finished writing rules to temporary file");

            info!(ctx.logger, "Applying rules (using nft)");
            let output = Command::new("nft").arg("-f").arg(rule_file_path).output()?;
            if !output.status.success() {
                return Err(DFWError::NFTablesError {
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                }
                .into());
            } else {
                return Ok(());
            }
        }

        Ok(())
    }
}

/// Representation of nftables table-families.
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
