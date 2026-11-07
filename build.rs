// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

fn main() {
    let major = env!("CARGO_PKG_VERSION_MAJOR");
    println!(r#"cargo:rustc-cfg=crate_major_version="{major}""#);
    println!(r#"cargo:rustc-check-cfg=cfg(crate_major_version, values("{major}"))"#);
}
