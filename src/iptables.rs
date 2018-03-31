// Copyright 2017, 2018 Pit Kleyersburg <pitkley@googlemail.com>
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

macro_rules! proxy {
    ( $name:ident ( $( $param:ident : $ty:ty ),+ ) -> $ret:ty ) => {
        fn $name(&self, $( $param: $ty ),+) -> Result<$ret> {
            (self.0).$name($($param),+).map_err(Into::into)
        }
    };
}

macro_rules! proxies {
    ( $( $name:ident ( $( $param:ident : $ty:ty ),+ ) -> $ret:ty );+ ) => {
        $( proxy!( $name ( $( $param : $ty ),+ ) -> $ret ); )+
    };
}

impl IPTables for IPTablesProxy {
    proxies! {
        get_policy(table: &str, chain: &str) -> String;
        set_policy(table: &str, chain: &str, policy: &str) -> bool;
        execute(table: &str, command: &str) -> Output;
        exists(table: &str, chain: &str, rule: &str) -> bool;
        chain_exists(table: &str, chain: &str) -> bool;
        insert(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        insert_unique(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        replace(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        append(table: &str, chain: &str, rule: &str) -> bool;
        append_unique(table: &str, chain: &str, rule: &str) -> bool;
        append_replace(table: &str, chain: &str, rule: &str) -> bool;
        delete(table: &str, chain: &str, rule: &str) -> bool;
        delete_all(table: &str, chain: &str, rule: &str) -> bool;
        list(table: &str, chain: &str) -> Vec<String>;
        list_table(table: &str) -> Vec<String>;
        list_chains(table: &str) -> Vec<String>;
        new_chain(table: &str, chain: &str) -> bool;
        flush_chain(table: &str, chain: &str) -> bool;
        rename_chain(table: &str, old_chain: &str, new_chain: &str) -> bool;
        delete_chain(table: &str, chain: &str) -> bool;
        flush_table(table: &str) -> bool
    }
}

/// [`IPTables`](trait.IPTables.html) implementation which does not interact with the iptables
/// binary and does not modify the rules active on the host.
///
/// This is currently used when running `dfw --dry-run`.
pub struct IPTablesDummy;

macro_rules! dummy {
    ( $name:ident ( $( $param:ident : $ty:ty ),+ ) -> $ret:ty ) => {
        fn $name(&self, $( $param: $ty ),+) -> Result<$ret> {
            Ok(Default::default())
        }
    };
}

macro_rules! dummies {
    ( $( $name:ident ( $( $param:ident : $ty:ty ),+ ) -> $ret:ty );+ ) => {
        $( dummy!( $name ( $( $param : $ty ),+ ) -> $ret ); )+
    };
}

#[allow(unused_variables)]
impl IPTables for IPTablesDummy {
    dummies! {
        get_policy(table: &str, chain: &str) -> String;
        set_policy(table: &str, chain: &str, policy: &str) -> bool;
        exists(table: &str, chain: &str, rule: &str) -> bool;
        chain_exists(table: &str, chain: &str) -> bool;
        insert(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        insert_unique(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        replace(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        append(table: &str, chain: &str, rule: &str) -> bool;
        append_unique(table: &str, chain: &str, rule: &str) -> bool;
        append_replace(table: &str, chain: &str, rule: &str) -> bool;
        delete(table: &str, chain: &str, rule: &str) -> bool;
        delete_all(table: &str, chain: &str, rule: &str) -> bool;
        list(table: &str, chain: &str) -> Vec<String>;
        list_table(table: &str) -> Vec<String>;
        list_chains(table: &str) -> Vec<String>;
        new_chain(table: &str, chain: &str) -> bool;
        flush_chain(table: &str, chain: &str) -> bool;
        rename_chain(table: &str, old_chain: &str, new_chain: &str) -> bool;
        delete_chain(table: &str, chain: &str) -> bool;
        flush_table(table: &str) -> bool
    }

    fn execute(&self, table: &str, command: &str) -> Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(9),
            stdout: vec![],
            stderr: vec![],
        })
    }
}

/// [`IPTables`](trait.IPTables.html) implementation which does not interact with the iptables
/// binary and does not modify the rules active on the host. It does keep a log of every action
/// executed.
#[derive(Default)]
pub struct IPTablesLogger {
    logs: RefCell<Vec<(String, String)>>,
}

impl IPTablesLogger {
    /// Create a new instance of `IPTablesLogger`
    pub fn new() -> IPTablesLogger {
        IPTablesLogger {
            logs: RefCell::new(Vec::new()),
        }
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

macro_rules! logger {
    ( $name:ident ( $( $param:ident : $ty:ty ),+ ) -> $ret:ty ) => {
        fn $name(&self, $( $param: $ty ),+) -> Result<$ret> {
            self.log(stringify!($name), &[ $( &$param.to_string() ),+ ]);
            Ok(Default::default())
        }
    };
}

macro_rules! loggers {
    ( $( $name:ident ( $( $param:ident : $ty:ty ),+ ) -> $ret:ty );+ ) => {
        $( logger!( $name ( $( $param : $ty ),+ ) -> $ret ); )+
    };
}

impl IPTables for IPTablesLogger {
    loggers! {
        get_policy(table: &str, chain: &str) -> String;
        set_policy(table: &str, chain: &str, policy: &str) -> bool;
        exists(table: &str, chain: &str, rule: &str) -> bool;
        chain_exists(table: &str, chain: &str) -> bool;
        insert(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        insert_unique(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        replace(table: &str, chain: &str, rule: &str, position: i32) -> bool;
        append(table: &str, chain: &str, rule: &str) -> bool;
        append_unique(table: &str, chain: &str, rule: &str) -> bool;
        append_replace(table: &str, chain: &str, rule: &str) -> bool;
        delete(table: &str, chain: &str, rule: &str) -> bool;
        delete_all(table: &str, chain: &str, rule: &str) -> bool;
        list(table: &str, chain: &str) -> Vec<String>;
        list_table(table: &str) -> Vec<String>;
        list_chains(table: &str) -> Vec<String>;
        new_chain(table: &str, chain: &str) -> bool;
        flush_chain(table: &str, chain: &str) -> bool;
        rename_chain(table: &str, old_chain: &str, new_chain: &str) -> bool;
        delete_chain(table: &str, chain: &str) -> bool;
        flush_table(table: &str) -> bool
    }

    fn execute(&self, table: &str, command: &str) -> Result<Output> {
        self.log("execute", &[table, command]);
        Ok(Output {
            status: ExitStatus::from_raw(9),
            stdout: vec![],
            stderr: vec![],
        })
    }
}
