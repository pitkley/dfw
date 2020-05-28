// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

use version_compare::Version;

fn main() {
    let crate_version = Version::from(env!("CARGO_PKG_VERSION")).unwrap();

    println!(
        r#"cargo:rustc-cfg=crate_major_version="{}""#,
        crate_version.part(0).unwrap()
    );
}
