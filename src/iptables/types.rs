// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! The types in this module make up the structure of the iptables backend-specific configurations.
//!
//! # Example
//!
//! ```
//! # use dfw::iptables::Iptables;
//! # use dfw::types::*;
//! # use toml;
//! # toml::from_str::<DFW<Iptables>>(r#"
//! [backend_defaults.initialization.v4]
//! filter = [
//!     "-P INPUT DROP",
//!     "-F INPUT",
//! ]
//! [backend_defaults.initialization.v6]
//! nat = [
//!     "-P PREROUTING DROP",
//! ]
//! # "#).unwrap();
//! ```

use serde::Deserialize;
use std::collections::HashMap;

/// The defaults/configuration for the iptables backend.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// The optional initialization section.
    ///
    /// # Example
    ///
    /// ```
    /// # use dfw::iptables::types::*;
    /// # use toml;
    /// # toml::from_str::<Defaults>(r#"
    /// [initialization.v4]
    /// filter = [
    ///     "-P INPUT DROP",
    ///     "-F INPUT",
    /// ]
    /// # "#).unwrap();
    ///
    /// # toml::from_str::<Defaults>(r#"
    /// [initialization.v6]
    /// nat = [
    ///     "-P PREROUTING DROP",
    /// ]
    /// # "#).unwrap();
    /// ```
    pub initialization: Option<Initialization>,
}

/// The initialization section allows you to add custom rules to any table in both iptables and
/// ip6tables.
///
/// # Example
///
/// ```
/// # use dfw::iptables::types::*;
/// # use toml;
/// # toml::from_str::<Defaults>(r#"
/// [initialization.v4]
/// filter = [
///     "-P INPUT DROP",
///     "-F INPUT",
/// ]
///
/// [initialization.v6]
/// nat = [
///     "-P PREROUTING DROP",
/// ]
/// # "#).unwrap();
/// ```
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Initialization {
    /// Initialization rules for iptables (IPv4). Expects a map where the key is a specific table
    /// and the value is a list of rules.
    ///
    /// # Example
    ///
    /// ```
    /// # use dfw::iptables::types::*;
    /// # use toml;
    /// # toml::from_str::<Defaults>(r#"
    /// [initialization.v4]
    /// filter = [
    ///     "-P INPUT DROP",
    ///     "-F INPUT",
    /// ]
    /// # "#).unwrap();
    /// ```
    pub v4: Option<HashMap<String, Vec<String>>>,

    /// Initialization rules for ip6tables (IPv6). Expects a map where the key is a specific table
    /// and the value is a list of rules.
    ///
    /// # Example
    ///
    /// ```
    /// # use dfw::iptables::types::*;
    /// # use toml;
    /// # toml::from_str::<Defaults>(r#"
    /// [initialization.v6]
    /// nat = [
    ///     "-P PREROUTING DROP",
    /// ]
    /// # "#).unwrap();
    /// ```
    pub v6: Option<HashMap<String, Vec<String>>>,
}
