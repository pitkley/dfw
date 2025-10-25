// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! Errors, using [`failure`][failure].
//!
//! [failure]: https://crates.io/crates/failure

#![allow(missing_docs, non_local_definitions)]

use failure::{Error, Fail};

#[derive(Debug, Fail)]
pub enum DFWError {
    #[fail(display = "NFTables error: \n{}\n{}", stdout, stderr)]
    NFTablesError { stdout: String, stderr: String },
    #[fail(display = "trait method unimplemented: {}", method)]
    TraitMethodUnimplemented { method: String },
}

pub type Result<E> = ::std::result::Result<E, Error>;
