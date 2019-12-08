//! TODO: write documentation

#![allow(missing_docs)]

use crate::errors::*;
use crate::nftables::RuleVerdict;
use crate::process::DFW_MARK;
use derive_builder::Builder;
use failure::bail;

#[derive(Debug, Clone, Builder)]
#[builder(derive(Debug), pattern = "mutable", build_fn(skip))]
pub struct Rule {
    #[builder(setter(into))]
    pub in_interface: String,
    #[builder(setter(into))]
    pub out_interface: String,
    #[builder(setter(into))]
    pub source_address: String,
    #[builder(setter(into))]
    pub destination_address: String,
    #[builder(setter(into))]
    pub source_address_v6: String,
    #[builder(setter(into))]
    pub destination_address_v6: String,
    #[builder(setter(into))]
    pub protocol: String,
    #[builder(setter(into))]
    pub source_port: String,
    #[builder(setter(into))]
    pub destination_port: String,
    #[builder(setter(into))]
    pub matches: String,
    #[builder(setter(into))]
    pub comment: String,
    #[builder(setter(into))]
    pub verdict: RuleVerdict,
    #[builder(setter(into))]
    pub dnat: String,
}

impl RuleBuilder {
    pub fn build(&self) -> Result<String> {
        let mut args: Vec<String> = Vec::new();

        // Handle protocol matches
        if self.source_port.is_some() || self.destination_port.is_some() {
            args.push(self.protocol.clone().unwrap_or_else(|| "tcp".to_owned()));
            if let Some(source_port) = &self.source_port {
                args.push("sport".to_owned());
                args.push(source_port.to_owned());
            }
            if let Some(destination_port) = &self.destination_port {
                args.push("dport".to_owned());
                args.push(destination_port.to_owned());
            }
        }

        // Handle `ip` matches
        if let Some(source_address) = &self.source_address {
            args.push("ip".to_owned());
            args.push("saddr".to_owned());
            args.push(source_address.to_owned());
        }
        if let Some(destination_address) = &self.destination_address {
            args.push("ip".to_owned());
            args.push("daddr".to_owned());
            args.push(destination_address.to_owned());
        }

        // Handle `ip6` matches
        if let Some(source_address) = &self.source_address_v6 {
            args.push("ip6".to_owned());
            args.push("saddr".to_owned());
            args.push(source_address.to_owned());
        }
        if let Some(destination_address) = &self.destination_address_v6 {
            args.push("ip6".to_owned());
            args.push("daddr".to_owned());
            args.push(destination_address.to_owned());
        }

        // Handle interface-matches
        if self.in_interface.is_some() || self.out_interface.is_some() {
            args.push("meta".to_owned());
            if let Some(in_interface) = &self.in_interface {
                args.push("iifname".to_owned());
                args.push(in_interface.to_owned());
            }
            if let Some(out_interface) = &self.out_interface {
                args.push("oifname".to_owned());
                args.push(out_interface.to_owned());
            }
        }

        // Bail if none of the above was initialized
        if args.is_empty() {
            bail!("one of `{source,destination}_{port,address{,_v6}}`, `{in,out}_interface` must be initialized");
        }

        // Unconditionally set mark
        args.push("meta".to_owned());
        args.push("mark".to_owned());
        args.push("set".to_owned());
        args.push(DFW_MARK.to_owned());

        if let Some(matches) = &self.matches {
            args.push(matches.to_owned());
        }

        if let Some(verdict) = &self.verdict {
            args.push(verdict.to_string());
        } else if let Some(dnat) = &self.dnat {
            args.push("dnat".to_owned());
            args.push(dnat.to_owned());
        }

        if let Some(comment) = &self.comment {
            args.push(format!(r#"comment "{}""#, comment));
        }

        Ok(args.join(" "))
    }
}
