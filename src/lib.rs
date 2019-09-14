// Copyright 2017 - 2019 Pit Kleyersburg <pitkley@googlemail.com>
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
pub mod errors;
pub mod nftables;
pub mod process;
pub mod rule;
pub mod types;
pub mod util;

// re-export process types
pub use process::*;
