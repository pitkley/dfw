// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

use crate::errors::*;
use failure::bail;

#[derive(Debug, Clone)]
pub(super) struct Rule {
    pub table: String,
    pub chain: String,

    pub source: Option<String>,
    pub destination: Option<String>,

    pub in_interface: Option<String>,
    pub out_interface: Option<String>,

    pub not_in_interface: bool,
    pub not_out_interface: bool,

    pub protocol: Option<String>,
    pub source_port: Option<String>,
    pub destination_port: Option<String>,

    pub filter: Option<String>,
    pub jump: Option<String>,

    pub comment: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct BuiltRule {
    pub table: String,
    pub chain: String,
    pub rule: String,
}

impl slog::Value for BuiltRule {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        format!("{:?}", self).serialize(record, key, serializer)
    }
}

#[allow(dead_code)]
impl Rule {
    pub(super) fn new(table: &str, chain: &str) -> Rule {
        Rule {
            table: table.into(),
            chain: chain.into(),
            source: None,
            destination: None,
            in_interface: None,
            out_interface: None,
            not_in_interface: false,
            not_out_interface: false,
            protocol: None,
            source_port: None,
            destination_port: None,
            filter: None,
            jump: None,
            comment: None,
        }
    }

    pub fn source<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.source = Some(value.as_ref().into());
        new
    }

    pub fn destination<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.destination = Some(value.as_ref().into());
        new
    }

    pub fn in_interface<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.in_interface = Some(value.as_ref().into());
        new
    }

    pub fn out_interface<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.out_interface = Some(value.as_ref().into());
        new
    }

    pub fn not_in_interface(&mut self, value: bool) -> &mut Self {
        let new = self;
        new.not_in_interface = value;
        new
    }

    pub fn not_out_interface(&mut self, value: bool) -> &mut Self {
        let new = self;
        new.not_out_interface = value;
        new
    }

    pub fn protocol<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.protocol = Some(value.as_ref().into());
        new
    }

    pub fn source_port<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.source_port = Some(value.as_ref().into());
        new
    }

    pub fn destination_port<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.destination_port = Some(value.as_ref().into());
        new
    }

    pub fn filter<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.filter = Some(value.as_ref().into());
        new
    }

    pub fn jump<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.jump = Some(value.as_ref().into());
        new
    }

    pub fn comment<S: ?Sized>(&mut self, value: &S) -> &mut Self
    where
        S: AsRef<str>,
    {
        let new = self;
        new.comment = Some(value.as_ref().into());
        new
    }

    pub fn build(&self) -> Result<BuiltRule> {
        let mut args: Vec<String> = Vec::new();

        if let Some(ref source) = self.source {
            args.push("-s".to_owned());
            args.push(source.to_owned());
        }
        if let Some(ref destination) = self.destination {
            args.push("-d".to_owned());
            args.push(destination.to_owned());
        }
        if let Some(ref in_interface) = self.in_interface {
            if self.not_in_interface {
                args.push("!".to_owned());
            }
            args.push("-i".to_owned());
            args.push(in_interface.to_owned());
        }
        if let Some(ref out_interface) = self.out_interface {
            if self.not_out_interface {
                args.push("!".to_owned());
            }
            args.push("-o".to_owned());
            args.push(out_interface.to_owned());
        }

        if let Some(ref protocol) = self.protocol {
            args.push("-p".to_owned());
            args.push(protocol.to_owned());
        } else if self.source_port.is_some() || self.destination_port.is_some() {
            // Source and destination ports require that the protocol is set.
            // If it hasn't been specified explicitly, use "tcp" as default.
            args.push("-p".to_owned());
            args.push("tcp".to_owned());
        }

        if let Some(ref source_port) = self.source_port {
            args.push("--sport".to_owned());
            args.push(source_port.to_owned());
        }

        if let Some(ref destination_port) = self.destination_port {
            args.push("--dport".to_owned());
            args.push(destination_port.to_owned());
        }

        if let Some(ref filter) = self.filter {
            args.push(filter.to_owned());
        }

        // Bail if none of the above was initialized
        if args.is_empty() {
            bail!(
                "one of `source`, `destination`, `in_interface`, `out_interface` \
                 `protocol`, `source_port`, `destination_port` or `filter` must  be \
                 initialized"
            );
        }

        if let Some(ref jump) = self.jump {
            args.push("-j".to_owned());
            args.push(jump.to_owned());
        } else {
            bail!("`jump` must be initialized");
        }

        if let Some(ref comment) = self.comment {
            args.push("-m".to_owned());
            args.push("comment".to_owned());
            args.push("--comment".to_owned());
            args.push(format!("\"{}\"", comment));
        }

        Ok(BuiltRule {
            table: self.table.clone(),
            chain: self.chain.clone(),
            rule: args.join(" "),
        })
    }
}
