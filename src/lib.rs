// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! # DFW - Docker Firewall Framework in Rust
//!
//! For detailed introductions, see the [README][github-readme].
//!
//! [github-readme]: https://github.com/pitkley/dfw#readme
//!
//! ## License
//!
//! DFW is licensed under either of
//!
//! * Apache License, Version 2.0, (<http://www.apache.org/licenses/LICENSE-2.0>)
//! * MIT license (<https://opensource.org/licenses/MIT>)
//!
//! at your option.

// Increase the compiler's recursion limit for the `error_chain` crate.
#![recursion_limit = "1024"]
#![deny(missing_docs)]

// declare modules
mod de;
pub mod errors;
pub mod iptables;
pub mod nftables;
pub mod process;
pub mod types;
pub mod util;

use errors::Result;
// re-export process types
pub use process::*;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use types::DFW;

/// This trait is used to distinguish between different firewall backends.
///
/// To add a new firewall-backend create an empty struct implementing this trait.
pub trait FirewallBackend: Sized
where
    DFW<Self>: Process<Self>,
{
    /// Associated type identifying the rule-type returned.
    type Rule;
    /// Associated type representing the firewall backend defaults/configuration.
    type Defaults: Debug + DeserializeOwned;

    /// Apply the processed rules.
    fn apply(rules: Vec<Self::Rule>, ctx: &ProcessContext<Self>) -> Result<()>;
}
