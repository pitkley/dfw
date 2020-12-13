// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! This module implements the iptables backend for DFW.

use crate::{errors::*, FirewallBackend, ProcessContext};
use failure::format_err;
use slog::info;
use std::{
    collections::BTreeMap,
    io::{BufWriter, Write},
    process::{Command, Stdio},
    str,
};
use strum::EnumDiscriminants;

mod process;
mod rule;
pub mod types;

const DFW_FORWARD_CHAIN: &str = "DFWRS_FORWARD";
const DFW_INPUT_CHAIN: &str = "DFWRS_INPUT";
const DFW_POSTROUTING_CHAIN: &str = "DFWRS_POSTROUTING";
const DFW_PREROUTING_CHAIN: &str = "DFWRS_PREROUTING";

const COMMAND_IPTABLES_RESTORE: &str = "iptables-restore";
const COMMAND_IP6TABLES_RESTORE: &str = "ip6tables-restore";

type Table = String;
type Chain = String;
type Policy = String;
type Rule = String;

/// Marker struct to implement iptables as a firewall backend.
#[derive(Debug)]
pub struct Iptables;
impl FirewallBackend for Iptables {
    type Rule = IptablesRule;
    type Defaults = types::Defaults;

    fn apply(rules: Vec<Self::Rule>, ctx: &ProcessContext<Self>) -> Result<()> {
        if ctx.dry_run {
            info!(ctx.logger, "Performing dry-run, will not update any rules");
        } else {
            info!(
                ctx.logger,
                "Applying IPv4 rules (using {})", COMMAND_IPTABLES_RESTORE
            );
            Self::restore(IptablesRuleDiscriminants::V4, rules.clone())?;
            info!(
                ctx.logger,
                "Applying IPv6 rules (using {})", COMMAND_IP6TABLES_RESTORE
            );
            Self::restore(IptablesRuleDiscriminants::V6, rules)?;
        }
        Ok(())
    }
}

impl Iptables {
    fn restore(
        rule_discriminant: IptablesRuleDiscriminants,
        rules: Vec<IptablesRule>,
    ) -> Result<()> {
        let command = match rule_discriminant {
            IptablesRuleDiscriminants::V4 => COMMAND_IPTABLES_RESTORE,
            IptablesRuleDiscriminants::V6 => COMMAND_IP6TABLES_RESTORE,
        };
        let mut process = Command::new(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Get process stdin, write format as expected by iptables-restore
        match process.stdin.as_mut() {
            Some(s) => Self::write_rules(rules, rule_discriminant, s)?,
            None => return Err(format_err!("cannot get stdin of {}", command)),
        }

        // Check exit status of command
        let output = process.wait_with_output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format_err!(
                "{} failed: '{}'",
                command,
                str::from_utf8(&output.stderr).unwrap_or("").trim(),
            ))
        }
    }

    /// Retrieve the current text that would be passed to `iptables-restore` as a vector of lines.
    pub fn get_rules(
        rules: Vec<IptablesRule>,
        rule_discriminant: IptablesRuleDiscriminants,
    ) -> Vec<String> {
        // Create a writer for around a vector
        let mut w = BufWriter::new(Vec::new());
        // Write the rules into the writer (and hence into the vector)
        Self::write_rules(rules, rule_discriminant, &mut w).unwrap();
        // Retrieve the vector from the writer
        let v = w.into_inner().unwrap();
        // Transform the `Vec<u8>` into `&str` (this can happen unsafely because the input provided
        // comes from DFW and is UTF-8)
        let s = unsafe { str::from_utf8_unchecked(&v) };

        // Trim whitespace, split on newlines, make owned and collect into `Vec<String>`
        s.trim().split('\n').map(|e| e.to_owned()).collect()
    }

    /// Write the rules in iptables-restore format to a given writer.
    ///
    /// (Used internally by `apply` and in tests to verify correct output.)
    fn write_rules<W: Write>(
        rules: Vec<IptablesRule>,
        rule_discriminant: IptablesRuleDiscriminants,
        w: &mut W,
    ) -> Result<()> {
        #[allow(clippy::type_complexity)]
        let mut rule_map: BTreeMap<Table, BTreeMap<Chain, (Option<Policy>, Vec<Rule>)>> =
            BTreeMap::new();
        for rule in rules {
            if rule_discriminant != (&rule).into() {
                continue;
            }
            match rule.policy_or_rule() {
                PolicyOrRule::Policy {
                    table,
                    chain,
                    policy,
                } => {
                    rule_map
                        .entry(table.to_owned())
                        .or_insert_with(BTreeMap::new)
                        .entry(chain.to_owned())
                        .or_insert_with(|| (None, Vec::new()))
                        .0 = Some(policy.to_owned());
                }
                PolicyOrRule::Rule {
                    table,
                    chain,
                    value,
                } => {
                    rule_map
                        .entry(table.to_owned())
                        .or_insert_with(BTreeMap::new)
                        .entry(chain.to_owned())
                        .or_insert_with(|| (None, Vec::new()))
                        .1
                        .push(value.to_owned());
                }
            }
        }

        for (table, chains) in rule_map.iter() {
            writeln!(w, "*{}", table)?;
            for (chain, (policy, _)) in chains.iter() {
                if let Some(policy) = policy {
                    writeln!(w, ":{} {} [0:0]", chain, policy)?;
                }
            }
            for (_, (_, rules)) in chains.iter() {
                for rule in rules {
                    writeln!(w, "{}", rule)?;
                }
            }
            writeln!(w, "COMMIT")?;
        }

        Ok(())
    }
}

/// Rule representation for iptables firewall backend.
#[derive(Debug, Clone, EnumDiscriminants)]
pub enum IptablesRule {
    /// IPv4
    V4(PolicyOrRule),
    /// IPv6
    V6(PolicyOrRule),
}

impl IptablesRule {
    fn policy_or_rule(&self) -> &PolicyOrRule {
        match self {
            Self::V4(policy_or_rule) => policy_or_rule,
            Self::V6(policy_or_rule) => policy_or_rule,
        }
    }

    pub(crate) fn from_discriminant(
        discriminant: IptablesRuleDiscriminants,
        policy_or_rule: PolicyOrRule,
    ) -> Self {
        match discriminant {
            IptablesRuleDiscriminants::V4 => IptablesRule::V4(policy_or_rule),
            IptablesRuleDiscriminants::V6 => IptablesRule::V6(policy_or_rule),
        }
    }
}

/// Policy or rule representation for iptables firewall backend.
#[derive(Debug, Clone)]
pub enum PolicyOrRule {
    /// Rule specifying a chain policy.
    Policy {
        /// Associated iptables table.
        table: String,
        /// Associated iptables chain.
        chain: String,
        /// Policy to set.
        policy: String,
    },
    /// Actual filter rule that will be added to a chain.
    Rule {
        /// Associated iptables table.
        table: String,
        /// Associated iptables chain.
        chain: String,
        /// The rule itself in valid iptables syntax.
        value: String,
    },
}
