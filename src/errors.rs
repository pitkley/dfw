// Copyright 2017, 2018 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! Errors, using [`error-chain`][error-chain].
//!
//! [error-chain]: https://crates.io/crates/error-chain

#![allow(missing_docs)]

error_chain! {
    foreign_links {
        Docker(::shiplift::errors::Error);
        Io(::std::io::Error);
        IPTError(::ipt::error::IPTError);
        TomlDe(::toml::de::Error);
    }
}
