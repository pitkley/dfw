// Copyright 2017 - 2019 Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! Utilities module

use crate::errors::*;

use futures::{sync::oneshot::spawn, Future};
use glob::glob;
use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use tokio::runtime::Runtime;
use toml;

lazy_static! {
    static ref RUNTIME: Runtime = Runtime::new().unwrap();
}

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

/// An extension trait for `Future` allowing synchronized execution of the future.
pub trait FutureExt: Future
where
    Self: Send + Sized + 'static,
    Self::Item: Send + 'static,
    Self::Error: Send + 'static,
{
    /// Execute future synchronously, blocking until a result can be returned.
    fn sync(self) -> std::result::Result<Self::Item, Self::Error> {
        spawn(self, &RUNTIME.executor()).wait()
    }
}

impl<T: Send + 'static, I: Send + 'static, E: Send + 'static> FutureExt for T where
    T: Future<Item = I, Error = E>
{
}
