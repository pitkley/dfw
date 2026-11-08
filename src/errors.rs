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
    #[error(
        "backend_options.packet_mark.preserve_mask {preserve_mask:#x} must retain DFW mark bits {required_bits:#x}"
    )]
    InvalidPacketMarkMask {
        preserve_mask: u32,
        required_bits: u32,
    },

    #[error("backend_options.packet_mark requires a concrete external interface name")]
    InvalidPacketMarkInterface,

    #[error("NFTables error: \n{stdout}\n{stderr}")]
    NFTablesError { stdout: String, stderr: String },
    #[error("trait method unimplemented: {method}")]
    TraitMethodUnimplemented { method: String },
}

pub type Result<E> = ::std::result::Result<E, Error>;
