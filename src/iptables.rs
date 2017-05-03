// Copyright 2017 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! This module holds the [`IPTables`](trait.IPTables.html) compatibility trait, allowing the use
//! of multiple implementations for the `IPTables` type of the [`rust-iptables`][rust-iptables]
//! crate.
//!
//! [rust-iptables]: https://crates.io/crates/iptables

use errors::*;
use std::cell::RefCell;
use std::convert::Into;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

/// Compatibility trait to generalize the API used by [`rust-iptables`][rust-iptables].
///
/// [rust-iptables]: https://crates.io/crates/iptables
pub trait IPTables {
    /// Get the default policy for a table/chain.
    fn get_policy(&self, table: &str, chain: &str) -> Result<String>;

    /// Set the default policy for a table/chain.
    fn set_policy(&self, table: &str, chain: &str, policy: &str) -> Result<bool>;

    /// Executes a given `command` on the chain.
    /// Returns the command output if successful.
    fn execute(&self, table: &str, command: &str) -> Result<Output>;

    /// Checks for the existence of the `rule` in the table/chain.
    /// Returns true if the rule exists.
    fn exists(&self, table: &str, chain: &str, rule: &str) -> Result<bool>;

    /// Checks for the existence of the `chain` in the table.
    /// Returns true if the chain exists.
    fn chain_exists(&self, table: &str, chain: &str) -> Result<bool>;

    /// Inserts `rule` in the `position` to the table/chain.
    /// Returns `true` if the rule is inserted.
    fn insert(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool>;

    /// Inserts `rule` in the `position` to the table/chain if it does not exist.
    /// Returns `true` if the rule is inserted.
    fn insert_unique(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool>;

    /// Replaces `rule` in the `position` to the table/chain.
    /// Returns `true` if the rule is replaced.
    fn replace(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool>;

    /// Appends `rule` to the table/chain.
    /// Returns `true` if the rule is appended.
    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<bool>;

    /// Appends `rule` to the table/chain if it does not exist.
    /// Returns `true` if the rule is appended.
    fn append_unique(&self, table: &str, chain: &str, rule: &str) -> Result<bool>;

    /// Appends or replaces `rule` to the table/chain if it does not exist.
    /// Returns `true` if the rule is appended or replaced.
    fn append_replace(&self, table: &str, chain: &str, rule: &str) -> Result<bool>;

    /// Deletes `rule` from the table/chain.
    /// Returns `true` if the rule is deleted.
    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<bool>;

    /// Deletes all repetition of the `rule` from the table/chain.
    /// Returns `true` if the rules are deleted.
    fn delete_all(&self, table: &str, chain: &str, rule: &str) -> Result<bool>;

    /// Lists rules in the table/chain.
    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>>;

    /// Lists rules in the table.
    fn list_table(&self, table: &str) -> Result<Vec<String>>;

    /// Lists the name of each chain in the table.
    fn list_chains(&self, table: &str) -> Result<Vec<String>>;

    /// Creates a new user-defined chain.
    /// Returns `true` if the chain is created.
    fn new_chain(&self, table: &str, chain: &str) -> Result<bool>;

    /// Flushes (deletes all rules) a chain.
    /// Returns `true` if the chain is flushed.
    fn flush_chain(&self, table: &str, chain: &str) -> Result<bool>;

    /// Renames a chain in the table.
    /// Returns `true` if the chain is renamed.
    fn rename_chain(&self, table: &str, old_chain: &str, new_chain: &str) -> Result<bool>;

    /// Deletes a user-defined chain in the table.
    /// Returns `true` if the chain is deleted.
    fn delete_chain(&self, table: &str, chain: &str) -> Result<bool>;

    /// Flushes all chains in a table.
    /// Returns `true` if the chains are flushed.
    fn flush_table(&self, table: &str) -> Result<bool>;
}

/// Proxying type for the `IPTables` type of the [`rust-iptables`][rust-iptables] crate.
///
/// This type exists to be able to implement the [`IPTables`-trait](trait.IPTables.html) for the
/// `IPTables`-type from the `rust-iptables` crate. This enables the use of different
/// implementations for `IPTables` in [`ProcessDFW`](../struct.ProcessDFW.html).
///
/// [rust-iptables]: https://crates.io/crates/iptables
pub struct IPTablesProxy(pub ::ipt::IPTables);

impl IPTables for IPTablesProxy {
    fn get_policy(&self, table: &str, chain: &str) -> Result<String> {
        self.0.get_policy(table, chain).map_err(Into::into)
    }

    fn set_policy(&self, table: &str, chain: &str, policy: &str) -> Result<bool> {
        self.0
            .set_policy(table, chain, policy)
            .map_err(Into::into)
    }

    fn execute(&self, table: &str, command: &str) -> Result<Output> {
        self.0.execute(table, command).map_err(Into::into)
    }

    fn exists(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.0.exists(table, chain, rule).map_err(Into::into)
    }

    fn chain_exists(&self, table: &str, chain: &str) -> Result<bool> {
        self.0.chain_exists(table, chain).map_err(Into::into)
    }

    fn insert(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        self.0
            .insert(table, chain, rule, position)
            .map_err(Into::into)
    }

    fn insert_unique(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        self.0
            .insert_unique(table, chain, rule, position)
            .map_err(Into::into)
    }

    fn replace(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        self.0
            .replace(table, chain, rule, position)
            .map_err(Into::into)
    }

    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.0.append(table, chain, rule).map_err(Into::into)
    }

    fn append_unique(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.0
            .append_unique(table, chain, rule)
            .map_err(Into::into)
    }

    fn append_replace(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.0
            .append_replace(table, chain, rule)
            .map_err(Into::into)
    }

    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.0.delete(table, chain, rule).map_err(Into::into)
    }

    fn delete_all(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.0
            .delete_all(table, chain, rule)
            .map_err(Into::into)
    }

    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>> {
        self.0.list(table, chain).map_err(Into::into)
    }

    fn list_table(&self, table: &str) -> Result<Vec<String>> {
        self.0.list_table(table).map_err(Into::into)
    }

    fn list_chains(&self, table: &str) -> Result<Vec<String>> {
        self.0.list_chains(table).map_err(Into::into)
    }

    fn new_chain(&self, table: &str, chain: &str) -> Result<bool> {
        self.0.new_chain(table, chain).map_err(Into::into)
    }

    fn flush_chain(&self, table: &str, chain: &str) -> Result<bool> {
        self.0.flush_chain(table, chain).map_err(Into::into)
    }

    fn rename_chain(&self, table: &str, old_chain: &str, new_chain: &str) -> Result<bool> {
        self.0
            .rename_chain(table, old_chain, new_chain)
            .map_err(Into::into)
    }

    fn delete_chain(&self, table: &str, chain: &str) -> Result<bool> {
        self.0.delete_chain(table, chain).map_err(Into::into)
    }

    fn flush_table(&self, table: &str) -> Result<bool> {
        self.0.flush_table(table).map_err(Into::into)
    }
}

/// [`IPTables`](trait.IPTables.html) implementation which does not interact with the iptables
/// binary and does not modify the rules active on the host.
///
/// This is currently used when running `dfwrs --dry-run`.
pub struct IPTablesDummy;
#[allow(unused_variables)]
impl IPTables for IPTablesDummy {
    fn get_policy(&self, table: &str, chain: &str) -> Result<String> {
        Ok("".to_owned())
    }

    fn set_policy(&self, table: &str, chain: &str, policy: &str) -> Result<bool> {
        Ok(false)
    }

    fn execute(&self, table: &str, command: &str) -> Result<Output> {
        Ok(Output {
               status: ExitStatus::from_raw(9),
               stdout: vec![],
               stderr: vec![],
           })
    }

    fn exists(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        Ok(false)
    }

    fn chain_exists(&self, table: &str, chain: &str) -> Result<bool> {
        Ok(false)
    }

    fn insert(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        Ok(false)
    }

    fn insert_unique(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        Ok(false)
    }

    fn replace(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        Ok(false)
    }

    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        Ok(false)
    }

    fn append_unique(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        Ok(false)
    }

    fn append_replace(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        Ok(false)
    }

    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        Ok(false)
    }

    fn delete_all(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        Ok(false)
    }

    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    fn list_table(&self, table: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    fn list_chains(&self, table: &str) -> Result<Vec<String>> {
        Ok(vec![])
    }

    fn new_chain(&self, table: &str, chain: &str) -> Result<bool> {
        Ok(false)
    }

    fn flush_chain(&self, table: &str, chain: &str) -> Result<bool> {
        Ok(false)
    }

    fn rename_chain(&self, table: &str, old_chain: &str, new_chain: &str) -> Result<bool> {
        Ok(false)
    }

    fn delete_chain(&self, table: &str, chain: &str) -> Result<bool> {
        Ok(false)
    }

    fn flush_table(&self, table: &str) -> Result<bool> {
        Ok(false)
    }
}

/// [`IPTables`](trait.IPTables.html) implementation which does not interact with the iptables
/// binary and does not modify the rules active on the host. It does keep a log of every action
/// executed.
pub struct IPTablesLogger {
    logs: RefCell<Vec<(String, String)>>,
}

impl IPTablesLogger {
    /// Create a new instance of `IPTablesLogger`
    pub fn new() -> IPTablesLogger {
        IPTablesLogger { logs: RefCell::new(Vec::new()) }
    }

    fn log(&self, function: &str, params: &[&str]) {
        self.logs
            .borrow_mut()
            .push((function.to_owned(), params.join(" ")));
    }

    /// Get the collected logs.
    pub fn logs(&self) -> Vec<(String, String)> {
        self.logs.borrow().clone()
    }
}

impl IPTables for IPTablesLogger {
    fn get_policy(&self, table: &str, chain: &str) -> Result<String> {
        self.log("get_policy", &[table, chain]);
        Ok("".to_owned())
    }

    fn set_policy(&self, table: &str, chain: &str, policy: &str) -> Result<bool> {
        self.log("set_policy", &[table, chain, policy]);
        Ok(false)
    }

    fn execute(&self, table: &str, command: &str) -> Result<Output> {
        self.log("execute", &[table, command]);
        Ok(Output {
               status: ExitStatus::from_raw(9),
               stdout: vec![],
               stderr: vec![],
           })
    }

    fn exists(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.log("exists", &[table, chain, rule]);
        Ok(false)
    }

    fn chain_exists(&self, table: &str, chain: &str) -> Result<bool> {
        self.log("chain_exists", &[table, chain]);
        Ok(false)
    }

    fn insert(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        let position = position.to_string();
        self.log("insert", &[table, chain, rule, &*position]);
        Ok(false)
    }

    fn insert_unique(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        let position = position.to_string();
        self.log("insert_unique", &[table, chain, rule, &*position]);
        Ok(false)
    }

    fn replace(&self, table: &str, chain: &str, rule: &str, position: i32) -> Result<bool> {
        let position = position.to_string();
        self.log("replace", &[table, chain, rule, &*position]);
        Ok(false)
    }

    fn append(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.log("append", &[table, chain, rule]);
        Ok(false)
    }

    fn append_unique(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.log("append_unique", &[table, chain, rule]);
        Ok(false)
    }

    fn append_replace(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.log("append_replace", &[table, chain, rule]);
        Ok(false)
    }

    fn delete(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.log("delete", &[table, chain, rule]);
        Ok(false)
    }

    fn delete_all(&self, table: &str, chain: &str, rule: &str) -> Result<bool> {
        self.log("delete_all", &[table, chain, rule]);
        Ok(false)
    }

    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>> {
        self.log("list", &[table, chain]);
        Ok(vec![])
    }

    fn list_table(&self, table: &str) -> Result<Vec<String>> {
        self.log("list_table", &[table]);
        Ok(vec![])
    }

    fn list_chains(&self, table: &str) -> Result<Vec<String>> {
        self.log("list_chains", &[table]);
        Ok(vec![])
    }

    fn new_chain(&self, table: &str, chain: &str) -> Result<bool> {
        self.log("new_chain", &[table, chain]);
        Ok(false)
    }

    fn flush_chain(&self, table: &str, chain: &str) -> Result<bool> {
        self.log("flush_chain", &[table, chain]);
        Ok(false)
    }

    fn rename_chain(&self, table: &str, old_chain: &str, new_chain: &str) -> Result<bool> {
        self.log("rename_chain", &[table, old_chain, new_chain]);
        Ok(false)
    }

    fn delete_chain(&self, table: &str, chain: &str) -> Result<bool> {
        self.log("delete_chain", &[table, chain]);
        Ok(false)
    }

    fn flush_table(&self, table: &str) -> Result<bool> {
        self.log("flush_table", &[table]);
        Ok(false)
    }
}
