// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! Errors returned by DFW.

#![allow(missing_docs)]

pub use anyhow::Error;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum DFWError {
    #[error("NFTables error: \n{stdout}\n{stderr}")]
    NFTablesError { stdout: String, stderr: String },
    #[error("trait method unimplemented: {method}")]
    TraitMethodUnimplemented { method: String },
}

pub type Result<E> = ::std::result::Result<E, Error>;
