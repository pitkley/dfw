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
use std::collections::BTreeMap;
use std::collections::HashMap as Map;
use std::convert::Into;
use std::io::BufWriter;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::str;

macro_rules! proxy {
    ( $( #[$attr:meta] )* $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty ) => {
        $( #[$attr] )*
        fn $name(&self $(, $param: $ty )*) -> Result<$ret> {
            (self.0).$name($($param),+).map_err(Into::into)
        }
    };
}

macro_rules! proxies {
    ( $( $( #[$attr:meta] )*
         $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty );+ $(;)* ) => {
        $( proxy!( $( #[$attr] )* $name ( $( $param : $ty ),* ) -> $ret ); )+
    };
}

// This macro uses some trickery to make the parameters passed to it available in the macro itself
// without blocking the use of those parameters at the call-site. If we would for example add the
// `table` and `chain` parameters to the macro pattern itself, those variables would become
// inaccessible at call-site due to macro-hygiene interpreting the parameters as regular tokens
// rather than idents.
//
// The trickery below uses two techniques:
//
// 1. Make all parameters available in a struct.
//    This allows us to access e.g. `p.table` without any further steps. Additionally, this confirms
//    at compile-time if the accessed parameter is available or not. Because of this we can not use
//    the same for the chain, that is `p.chain` only works on functions where the parameter chain
//    was passed. To work around this we use another trick.
//
// 2. Since the chain-parameter in `self.rule_map` is an `Option`, we predefine `chain_opt` with
//    `None` and then use automatically generated if-statements to replace it with `Some(chain)`.
//
// While this isn't particularly clean, my hope is that both the struct and the static ifs will be
// optimized away as much as possible, making this not affect runtime -- although this does not make
// it less ugly. :)
macro_rules! restore {
    ( $( #[$attr:meta] )*
      $name:ident ( $($param:ident : $ty:ty ),* )
      -> $ret:ty { $fmtstr:expr $(, $fmtid:ident)* } ) => {
        $( #[$attr] )*
        fn $name(&self $(, $param: $ty )*) -> Result<$ret> {
            #[allow(dead_code)]
            struct Params {
                $( $param: String ),*
            }
            let p = Params { $( $param: $param.to_string() ),* };
            let mut chain_opt = None;
            $( if stringify!($param) == "chain" {
                chain_opt = Some($param.to_owned());
            });*;

            let rule = format!($fmtstr, $($fmtid),*);
            self.rule_map
                .borrow_mut()
                .entry(p.table.clone())
                .or_insert_with(|| Map::new())
                .entry(chain_opt)
                .or_insert_with(|| Vec::new())
                .push(rule.clone());
            self.rules
                .borrow_mut()
                .entry(p.table)
                .or_insert_with(|| Vec::new())
                .push(rule);
            Ok(Default::default())
        }
    };
}

macro_rules! restores {
    ( $( $( #[$attr:meta] )*
      $name:ident ( $( $param:ident : $ty:ty ),* )
      -> $ret:ty { $fmtstr:tt $(,)* $($fmtid:ident),* } )+ $(;)* ) => {
        $( restore!( $( #[$attr] )*
                     $name ( $( $param : $ty ),* ) -> $ret { $fmtstr $(, $fmtid)* } ); )+
    };
}

macro_rules! unimplemented_method {
    ( $( #[$attr:meta] )* $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty ) => {
        $( #[$attr] )*
        #[allow(unused_variables)]
        fn $name(&self $(, $param: $ty )*) -> Result<$ret> {
            bail!(ErrorKind::TraitMethodUnimplemented(stringify!($name).to_owned()))
        }
    };
}

macro_rules! unimplemented_methods {
    ( $( $( #[$attr:meta] )*
         $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty );+ $(;)* ) => {
        $( unimplemented_method!( $( #[$attr] )* $name ( $( $param : $ty ),* ) -> $ret ); )+
    };
}

macro_rules! dummy {
    ( $( #[$attr:meta] )* $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty ) => {
        $( #[$attr] )*
        #[allow(unused_variables)]
        fn $name(&self $(, $param: $ty )*) -> Result<$ret> {
            Ok(Default::default())
        }
    };
}

macro_rules! dummies {
    ( $( $( #[$attr:meta] )*
         $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty );+ $(;)* ) => {
        $( dummy!( $( #[$attr] )* $name ( $( $param : $ty ),* ) -> $ret ); )+
    };
}

macro_rules! logger {
    ( $( #[$attr:meta] )* $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty ) => {
        fn $name(&self $(, $param: $ty )*) -> Result<$ret> {
            self.log(stringify!($name), &[ $( &$param.to_string() ),* ]);
            Ok(Default::default())
        }
    };
}

macro_rules! loggers {
    ( $( $( #[$attr:meta] )*
         $name:ident ( $( $param:ident : $ty:ty ),* ) -> $ret:ty );+ $(;)* ) => {
        $( logger!( $( #[$attr] )* $name ( $( $param : $ty ),* ) -> $ret ); )+
    };
}

/// Enum identifying a IP protocol version. Can be used by `IPTables` implementations to discern
/// between IPv4 rules and IPv6 rules.
pub enum IPVersion {
    /// IP protocol version 4
    IPv4,

    /// IP protocol version 6
    IPv6,
}

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

    /// Commit the changes queued.
    /// Only has an effect on some implementations
    fn commit(&self) -> Result<bool>;
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
        flush_table(table: &str) -> bool;
    }

    dummies! {
        commit() -> bool;
    }
}

/// [`IPTables`](trait.IPTables.html) implementation which tracks the functions called and maps it
/// to the text-format used by `iptables-restore`. Upon calling
/// [`IPTables::commit`](trait.IPTables.html#tymethod.commit) this text is then passed onto the
/// `iptables-restore` binary with the `--noflush` option enabled. This will have the following
/// effect:
///
/// * Any existing rules which **are not** part of chains created by DFW will not be removed on
///   commit *(unless initialization rules are specified which state otherwise)*
/// * Any rules which **are** part of chains created by DFW will be completely recreated
/// * The recreation of the rules happens atomically thanks to `iptables-restore`. This both cuts
///   down on the execution time and on the time were vital rules might be missing.
///
/// ## Note
///
/// A multitude of methods in this implementation are marked as "unsupported". This means that the
/// call is a no-op and will not execute anything -- but it also won't fail!
///
/// (Every method that is marked as unsupported also has a justification as to why it isn't
/// implemented, although for most the reason is that DFW doesn't require it and thus no effort was
/// made.)
pub struct IPTablesRestore {
    /// Save command to execute (`iptables-restore` or `ip6tables-restore`).
    cmd: &'static str,

    /// Rules are mapped: table -> chain -> rules
    ///
    /// ## Note
    ///
    /// `RefCell` is required because the struct cannot be borrowed mutably due to conflicts with
    /// the trait.
    rule_map: RefCell<Map<String, Map<Option<String>, Vec<String>>>>,

    /// List of rules tracking the order they were supplied by `ProcessDFW`
    ///
    /// ## Note
    ///
    /// `RefCell` is required because the struct cannot be borrowed mutably due to conflicts with
    /// the trait.
    rules: RefCell<BTreeMap<String, Vec<String>>>,
}

impl IPTablesRestore {
    /// Create a new instance of `IPTablesLogger`
    pub fn new(ip_version: IPVersion) -> Result<IPTablesRestore> {
        let cmd = match ip_version {
            IPVersion::IPv4 => "iptables-restore",
            IPVersion::IPv6 => "ip6tables-restore",
        };

        Ok(IPTablesRestore {
            cmd: cmd,
            rule_map: RefCell::new(Map::new()),
            rules: RefCell::new(BTreeMap::new()),
        })
    }

    /// Retrieve the current text that would be passed to `iptables-restore` as a vector of lines.
    pub fn get_rules(&self) -> Vec<String> {
        // Create a writer for around a vector
        let mut w = BufWriter::new(Vec::new());
        // Write the rules into the writer (and hence into the vector)
        self.write_rules(&mut w).unwrap();
        // Retrieve the vector from the writer
        let v = w.into_inner().unwrap();
        // Transform the `Vec<u8>` into `&str` (this can happen unsafely because the input provided
        // comes from DFW and is UTF8)
        let s = unsafe { str::from_utf8_unchecked(&v) };

        // Trim whitespace, split on newlines, make owned and collect into `Vec<String>`
        s.trim().split("\n").map(|e| e.to_owned()).collect()
    }

    /// Write the rules in iptables-restore format to a given writer.
    ///
    /// (Used internally by [`commit()`](#method.commit) and in tests to verify correct output.)
    fn write_rules<W: Write>(&self, w: &mut W) -> Result<()> {
        for (table, rules) in self.rules.borrow().iter() {
            writeln!(w, "*{}", table)?;
            writeln!(w, "{}", rules.join("\n"),)?;
            writeln!(w, "COMMIT")?;
        }

        Ok(())
    }
}

impl IPTables for IPTablesRestore {
    restores! {
        set_policy(table: &str, chain: &str, policy: &str) -> bool {
            ":{} {} [0:0]", chain, policy
        }

        append(table: &str, chain: &str, rule: &str) -> bool {
            "-A {} {}", chain, rule
        }

        delete(table: &str, chain: &str, rule: &str) -> bool {
            "-D {} {}", chain, rule
        }

        new_chain(table: &str, chain: &str) -> bool {
            ":{} - [0:0]", chain
        }

        flush_chain(table: &str, chain: &str) -> bool {
            "-F {}", chain
        }

        flush_table(table: &str) -> bool {
            "-F"
        }
    }

    fn execute(&self, table: &str, command: &str) -> Result<Output> {
        self.rule_map
            .borrow_mut()
            .entry(table.to_owned())
            .or_insert_with(|| Map::new())
            .entry(None)
            .or_insert_with(|| Vec::new())
            .push(format!("{}", command));
        Ok(Output {
            status: ExitStatus::from_raw(9),
            stdout: vec![],
            stderr: vec![],
        })
    }

    fn list(&self, table: &str, chain: &str) -> Result<Vec<String>> {
        Ok(self.rule_map
            .borrow()
            .get(table)
            .and_then(|v| v.get(&Some(chain.to_owned())))
            .map_or_else(|| vec![], |v| v.clone()))
    }

    fn list_table(&self, table: &str) -> Result<Vec<String>> {
        Ok(self.rule_map.borrow().get(table).map_or_else(
            || vec![],
            |v| {
                v.iter()
                    .filter(|&(k, _)| k.is_some())
                    .map(|(_, v)| v.clone())
                    .fold(vec![], |mut acc, mut v| {
                        acc.append(&mut v);
                        acc
                    })
            },
        ))
    }

    fn list_chains(&self, table: &str) -> Result<Vec<String>> {
        Ok(self.rule_map.borrow().get(table).map_or_else(
            || vec![],
            |v| v.keys().into_iter().filter_map(|k| k.clone()).collect(),
        ))
    }

    fn commit(&self) -> Result<bool> {
        // Start iptables-restore with `--noflush` option, attach to stdin and stdout
        let mut c = Command::new(self.cmd)
            .arg("--noflush")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        // Get process stdin, write format es expected by iptables-restore
        match c.stdin.as_mut() {
            Some(ref mut s) => self.write_rules(s)?,
            None => Err(format!("cannot get stdin of {}", self.cmd))?,
        }

        // Check exit status of command
        let output = c.wait_with_output()?;
        if output.status.success() {
            Ok(true)
        } else {
            Err(format!(
                "{} failed: '{}'",
                self.cmd,
                str::from_utf8(&output.stderr).unwrap_or("").trim()
            ))?
        }
    }

    // Every call that is not handled above will be ignored in `IPTablesRestore`.
    // The following calls are not implemented in `IPTablesRestore` and will return a
    // `TraitMethodUnimplemented` error. Below every call has a justification as to why it isn't
    // implemented. (Where most are not applicable to `iptables-restore` or DFW simply doesn't
    // require it and thus no effort was made at this point.)
    unimplemented_methods! {
        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// Inserting at a specific position -- while technically supported by iptables-restore
        /// because the order of the rules read is honored -- is not required in the context of dfw.
        /// None of the calls in `ProcessDFW` care about order, since no conflicting rules are
        /// created.
        insert(table: &str, chain: &str, rule: &str, position: i32) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// See [`IPTablesRestore::insert`](#method.insert).
        insert_unique(table: &str, chain: &str, rule: &str, position: i32) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// DFW does not require `append_unique`. Therefore no effort was made to replicate this
        /// functionality.
        append_unique(table: &str, chain: &str, rule: &str) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// DFW does not require `append_replace`. Therefore no effort was made to replicate this
        /// functionality.
        append_replace(table: &str, chain: &str, rule: &str) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// Getting a policy does not make sense in the context of `iptables-restore` since the only
        /// policies to get are the ones set by the same caller.
        get_policy(table: &str, chain: &str) -> String;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// Checking if a rule exists does not make sense in the context of `iptables-restore` since
        /// the only rules that could match are the ones appended by the same caller.
        exists(table: &str, chain: &str, rule: &str) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// Checking if a chain exists does not make sense in the context of `iptables-restore`
        /// since the only chains that could match are the ones created by the same caller.
        chain_exists(table: &str, chain: &str) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// Replacing a rule does not make sense in the context of `iptables-restore` since the only
        /// rules that could be replaced are the ones created by the same caller.
        replace(table: &str, chain: &str, rule: &str, position: i32) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// `delete_all` is a method supported by `iptables::IPTables` and includes logic to remove
        /// rules matching the rule string for as long as there are more rules that exist. This
        /// logic can not be replicated for `iptables-restore`.
        delete_all(table: &str, chain: &str, rule: &str) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// Renaming a chain does not make sense in the context of `iptables-restore` since the only
        /// chains that could be renamed are the ones created by the same caller.
        rename_chain(table: &str, old_chain: &str, new_chain: &str) -> bool;

        /// **METHOD UNSUPPORTED IN `IPTablesRestore`!**
        ///
        /// Deleting a chain does not make sense in the context of `iptables-restore` since the only
        /// chains that could be deleted are the ones created by the same caller.
        delete_chain(table: &str, chain: &str) -> bool;
    }
}

#[cfg(test)]
mod tests_iptablesrestore {
    use super::{IPTables, IPTablesRestore, IPVersion};

    macro_rules! test {
        ( $name:ident ( $ipt:ident ) $block:block -> [ $( $val:expr ),* ] ) => {
            #[test]
            fn $name() {
                let $ipt = IPTablesRestore::new(IPVersion::IPv4).unwrap();

                let _ = $block;

                let actual = $ipt.get_rules();
                let expected = vec![
                    $( $val ),* ,
                    "COMMIT",
                ].into_iter()
                    .map(|e| e.to_owned())
                    .collect::<Vec<_>>();

                assert_eq!(actual, expected);
            }
        }
    }

    macro_rules! tests {
        ( $( $name:ident ( $ipt:ident ) $block:block -> [ $( $val:expr ),* $(,)* ] $(;)* )* ) => {
            $( test!( $name ( $ipt ) $block -> [ $( $val ),* ] ); )*
        }
    }

    tests! {
        restore_set_policy(ipt) {
            ipt.set_policy("nat", "TEST_CHAIN", "DROP")
        } -> [
            "*nat",
            ":TEST_CHAIN DROP [0:0]",
        ]

        restore_append(ipt) {
            ipt.append("filter", "TEST_CHAIN", "-s 10.0.0.1 -j ACCEPT")
        } -> [
            "*filter",
            "-A TEST_CHAIN -s 10.0.0.1 -j ACCEPT",
        ]
    }
}

/// [`IPTables`](trait.IPTables.html) implementation which does not interact with the iptables
/// binary and does not modify the rules active on the host.
///
/// This is currently used when running `dfw --dry-run`.
pub struct IPTablesDummy;

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
        flush_table(table: &str) -> bool;
        commit() -> bool;
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
    /// ## Note
    ///
    /// `RefCell` is required because the struct cannot be borrowed mutably due to conflicts with
    /// the trait.
    logs: RefCell<Vec<(String, Option<String>)>>,
}

impl IPTablesLogger {
    /// Create a new instance of `IPTablesLogger`
    pub fn new() -> IPTablesLogger {
        IPTablesLogger {
            logs: RefCell::new(Vec::new()),
        }
    }

    fn log(&self, function: &str, params: &[&str]) {
        self.logs.borrow_mut().push((
            function.to_owned(),
            if params.is_empty() {
                None
            } else {
                Some(params.join(" "))
            },
        ));
    }

    /// Get the collected logs.
    pub fn logs(&self) -> Vec<(String, Option<String>)> {
        self.logs.borrow().clone()
    }
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
        flush_table(table: &str) -> bool;
        commit() -> bool;
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
