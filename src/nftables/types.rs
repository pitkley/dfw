// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! The types in this module make up the structure of the nftables backend-specific configurations.
//!
//! # Example
//!
//! ```
//! # use dfw::nftables::Nftables;
//! # use dfw::types::*;
//! # use toml;
//! # toml::from_str::<DFW<Nftables>>(r#"
//! [backend_defaults]
//! custom_tables = { name = "filter", chains = ["input", "forward"]}
//!
//! [backend_defaults.initialization]
//! rules = [
//!     "add table inet custom",
//! ]
//! # "#).unwrap();
//! ```

use crate::de::*;
use serde::Deserialize;

/// The defaults/configuration for the nftables backend.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Specify the names of custom nft-tables that should be partially managed.
    ///
    /// # Explanation
    ///
    /// If you want to use or already use an existing nftables table to manage rules independently
    /// from DFW, it is important that two conditions are met:
    ///
    /// 1. The priority-values of the chains are _lower_ than the priority-values used by DFW.
    /// 2. The default-policy of the any input or forward chains in the table are set to `accept`.
    ///
    /// While DFW cannot ensure that the first condition is met (since changing the priority of a
    /// chain is not possible without recreating the chain), it can set the policies of your input
    /// and output chains to `accept` for you.
    ///
    /// # Example
    ///
    /// ```toml
    /// custom_tables = { name = "filter", chains = ["input", "forward"] }
    /// custom_tables = [
    ///     { name = "filter", chains = ["input", "forward"] },
    ///     { name = "custom", chains = ["input", "forward"] }
    /// ]
    /// ```
    #[serde(default, deserialize_with = "option_struct_or_seq_struct")]
    pub custom_tables: Option<Vec<Table>>,

    /// The optional initialization section.
    ///
    /// # Example
    ///
    /// ```toml
    /// [initialization]
    /// rules = [
    ///     "add table inet custom",
    ///     "flush table inet custom",
    ///     # ...
    /// ]
    /// ```
    pub initialization: Option<Initialization>,

    /// # This field is **DEPRECATED!**
    ///
    /// Provide the initilization rules in the [`rules` field] in the [`initialization`]
    /// section instead. (This field will be removed with release 2.0.0.)
    ///
    /// [`rules` field]: struct.Initialization.html#structfield.rules
    /// [`initialization`]: #structfield.initialization
    #[deprecated(
        since = "1.2.0",
        note = "Provide the custom tables in the nftables backend-defaults section instead. This \
                field will be removed with release 2.0.0."
    )]
    pub rules: Option<Vec<String>>,
}

/// Reference to an nftables table, specifically to the input- and forward-chains within it.
///
/// This is used by DFW when managing other tables is required.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[serde(deny_unknown_fields)]
pub struct Table {
    /// Name of the custom table.
    pub name: String,

    /// Names of the input and forward chains defined within the custom table.
    pub chains: Vec<String>,
}

/// The initialization section allows you to execute any commands against nftables.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Initialization {
    /// Initialization rules for nftables
    ///
    /// # Example
    ///
    /// ```toml
    /// [initialization]
    /// rules = [
    ///     "add table inet custom",
    ///     "flush table inet custom",
    ///     # ...
    /// ]
    /// ```
    pub rules: Option<Vec<String>>,
}
