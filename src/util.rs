// Copyright 2017 - 2019 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! Utilities module

use crate::errors::*;

use glob::glob;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use toml;

/// Load single TOML-file from path and deserialize it into type `T`.
pub fn load_file<T>(file: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut contents = String::new();
    let mut file = BufReader::new(File::open(file)?);
    file.read_to_string(&mut contents)?;
    Ok(toml::from_str(&contents)?)
}

/// Load all TOML-files from a path, concatenate their contents and deserialize the result into
/// type `T`.
pub fn load_path<T>(path: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut contents = String::new();
    for entry in glob(&format!("{}/*.toml", path)).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                let mut file = BufReader::new(File::open(path)?);
                file.read_to_string(&mut contents)?;
            }
            Err(e) => println!("{:?}", e),
        }
    }

    Ok(toml::from_str(&contents)?)
}
