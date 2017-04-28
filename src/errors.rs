// Copyright 2017 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

error_chain! {
    foreign_links {
        ClapError(::clap::Error);
        Docker(::shiplift::errors::Error);
        IPTError(::ipt::error::IPTError);
        Io(::std::io::Error);
        ParseError(::url::ParseError);
        ParseIntError(::std::num::ParseIntError);
        TomlSer(::toml::ser::Error);
        TomlDe(::toml::de::Error);
    }
}
