// Copyright Pit Kleyersburg <pitkley@googlemail.com>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

//! This module holds the types related to configuration processing and rule creation.

use crate::{errors::*, types::*, util::FutureExt, FirewallBackend};
use bollard::{
    container::ListContainersOptions,
    models::{ContainerSummaryInner, Network, NetworkContainer},
    Docker,
};
use failure::{bail, format_err};
use maplit::hashmap;
use slog::{debug, o, trace, Logger};
use std::collections::HashMap as Map;

/// This trait allows a type to define its own processing rules. It is expected to return a list
/// of rules that can be applied with nft.
///
/// # Example
///
/// ```
/// # use dfw::FirewallBackend;
/// # use dfw::process::{Process, ProcessContext};
/// # use dfw::types::DFW;
/// # use failure::Error;
/// struct MyBackend;
/// impl FirewallBackend for MyBackend {
///     type Rule = String;
/// #    type Defaults = ();
///
///     fn apply(rules: Vec<String>, ctx: &ProcessContext<Self>) -> Result<(), Error> {
///         // Write code to apply the processed rules.
/// #        unimplemented!()
///     }
/// }
/// # impl Process<MyBackend> for DFW<MyBackend> {
/// #     fn process(&self, ctx: &ProcessContext<MyBackend>) -> Result<Option<Vec<String>>, Error> {
/// #         unimplemented!()
/// #     }
/// # }
/// struct MyType {
///     rules: Vec<String>,
/// }
///
/// impl Process<MyBackend> for MyType {
///     fn process(&self, ctx: &ProcessContext<MyBackend>) -> Result<Option<Vec<String>>, Error> {
///         let mut rules = Vec::new();
///         for rule in &self.rules {
///             rules.push(format!("add rule {}", rule));
///         }
///         Ok(Some(rules))
///     }
/// }
/// ```
pub trait Process<B: FirewallBackend>
where
    DFW<B>: Process<B>,
{
    /// Process the current type within the given [`ProcessContext`], returning zero or more rules
    /// to apply with nft.
    ///
    /// [`ProcessContext`]: struct.ProcessContext.html
    fn process(&self, ctx: &ProcessContext<B>) -> Result<Option<Vec<B::Rule>>>;
}

impl<B, T> Process<B> for Option<T>
where
    B: FirewallBackend,
    DFW<B>: Process<B>,
    T: Process<B>,
{
    fn process(&self, ctx: &ProcessContext<B>) -> Result<Option<Vec<B::Rule>>> {
        match self {
            Some(t) => t.process(ctx),
            None => Ok(None),
        }
    }
}

impl<B, T> Process<B> for Vec<T>
where
    B: FirewallBackend,
    DFW<B>: Process<B>,
    T: Process<B>,
{
    fn process(&self, ctx: &ProcessContext<B>) -> Result<Option<Vec<B::Rule>>> {
        let mut rules = Vec::new();
        for rule in self {
            if let Some(mut sub_rules) = rule.process(ctx)? {
                rules.append(&mut sub_rules);
            }
        }

        Ok(Some(rules))
    }
}

/// Enclosing struct to manage rule processing.
pub struct ProcessContext<'a, B>
where
    B: FirewallBackend,
    DFW<B>: Process<B>,
{
    pub(crate) docker: &'a Docker,
    pub(crate) dfw: &'a DFW<B>,
    pub(crate) container_map: Map<String, ContainerSummaryInner>,
    pub(crate) network_map: Map<String, Network>,
    pub(crate) external_network_interfaces: Option<Vec<String>>,
    pub(crate) primary_external_network_interface: Option<String>,
    pub(crate) logger: Logger,
    pub(crate) dry_run: bool,
}

impl<'a, B> ProcessContext<'a, B>
where
    B: FirewallBackend,
    DFW<B>: Process<B>,
{
    /// Create a new instance of `ProcessDFW` for rule processing.
    pub fn new(
        docker: &'a Docker,
        dfw: &'a DFW<B>,
        processing_options: &'a ProcessingOptions,
        logger: &'a Logger,
        dry_run: bool,
    ) -> Result<ProcessContext<'a, B>> {
        let logger = logger.new(o!());

        let list_containers_options = match processing_options.container_filter {
            ContainerFilter::All => None,
            ContainerFilter::Running => Some(ListContainersOptions {
                filters: hashmap! { "status" => vec!["running"]},
                ..Default::default()
            }),
        };
        let containers = docker.list_containers(list_containers_options).sync()?;
        debug!(logger, "Got list of containers";
               o!("containers" => format!("{:#?}", containers)));

        let container_map = get_container_map(&containers);
        trace!(logger, "Got map of containers";
               o!("container_map" => format!("{:#?}", container_map)));

        let networks = docker.list_networks::<String>(None).sync()?;
        debug!(logger, "Got list of networks";
               o!("networks" => format!("{:#?}", networks)));

        let network_map =
            get_network_map(&networks).ok_or_else(|| format_err!("no networks found"))?;
        trace!(logger, "Got map of networks";
               o!("container_map" => format!("{:#?}", container_map)));

        let external_network_interfaces = dfw
            .global_defaults
            .external_network_interfaces
            .as_ref()
            .cloned();
        let primary_external_network_interface = external_network_interfaces
            .as_ref()
            .and_then(|v| v.get(0))
            .map(|s| s.to_owned());

        Ok(ProcessContext {
            docker,
            dfw,
            container_map,
            network_map,
            external_network_interfaces,
            primary_external_network_interface,
            logger,
            dry_run,
        })
    }

    /// Start the processing using the configuration given at creation.
    pub fn process(&mut self) -> Result<()> {
        let rules = Process::<B>::process(self.dfw, self)?;
        if let Some(rules) = rules {
            B::apply(rules, self)?;
        }

        Ok(())
    }
}

/// Option to filter the containers to be processed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerFilter {
    /// Process all containers, i.e. don't filter.
    All,
    /// Only process running containers.
    Running,
}

/// Options to configure the processing procedure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingOptions {
    /// Option to filter the containers to be processed, see
    /// [`ContainerFilter`](enum.ContainerFilter.html).
    pub container_filter: ContainerFilter,
}

impl Default for ProcessingOptions {
    fn default() -> Self {
        ProcessingOptions {
            container_filter: ContainerFilter::All,
        }
    }
}

pub(crate) fn get_bridge_name(network_id: &str) -> Result<String> {
    if network_id.len() < 12 {
        bail!("network has to be longer than 12 characters");
    }
    Ok(format!("br-{}", &network_id[..12]))
}

pub(crate) fn get_network_for_container(
    docker: &Docker,
    container_map: &Map<String, ContainerSummaryInner>,
    container_name: &str,
    network_id: &str,
) -> Result<Option<NetworkContainer>> {
    if let Some(container) = container_map.get(container_name) {
        Ok(docker
            .inspect_network::<String>(network_id, None)
            .sync()?
            .containers
            .and_then(|containers| {
                container
                    .id
                    .as_ref()
                    .and_then(|container_id| containers.get(container_id).cloned())
            }))
    } else {
        Ok(None)
    }
}

pub(crate) fn get_container_map(
    containers: &[ContainerSummaryInner],
) -> Map<String, ContainerSummaryInner> {
    let mut container_map: Map<String, ContainerSummaryInner> = Map::new();
    for container in containers {
        if let Some(names) = &container.names {
            for name in names {
                container_map.insert(
                    name.clone().trim_start_matches('/').to_owned(),
                    container.clone(),
                );
            }
        }
    }

    container_map
}

pub(crate) fn get_network_map(networks: &[Network]) -> Option<Map<String, Network>> {
    let mut network_map: Map<String, Network> = Map::new();
    for network in networks {
        if let Some(name) = &network.name {
            network_map.insert(name.clone(), network.clone());
        }
    }

    if network_map.is_empty() {
        None
    } else {
        Some(network_map)
    }
}

pub(crate) fn generate_marker(components: &[&str]) -> String {
    format!("DFW-MARKER:{}", components.join(";"))
}
