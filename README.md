# DFW - Docker Firewall Framework in Rust

## Breaking changes coming from v0.x to v1.x

Starting with version 1.0, DFW introduced the [nftables] backend and made it the default firewall-backend used.
If you are upgrading DFW but don't want to switch to nftables, you can provide the `--firewall-backend iptables` parameter to DFW (this requires at least DFW v1.2).

Please note that no matter if you transition to nftables or not, **v1.0 introduced breaking changes to the configuration**.
Please consult the [migration documentation][migration-v0.x-to-v1.2] on how to update your configuration.

[nftables]: https://netfilter.org/projects/nftables/

-----

1. [Overview](#overview)
    1. [Example](#overview-example)
2. [Getting started](#gettingstarted)
3. [Configuration](#configuration)
4. [IPv6 support](#ipv6support)
    1. [Example: webserver reachable via IPv6](#ipv6support-example)
5. [Supported Docker versions](#supporteddockerversions)
6. [Version bump policy](#versionbumppolicy)
7. [License](#license)
    1. [Contribution](#license-contribution)

-----

## <a name="overview"></a> Overview

DFW is conceptually based on the [Docker Firewall Framework, DFWFW][dfwfw-github].
Its goal is to make firewall administration with Docker simpler, but also more extensive by trying to replace the Docker built-in firewall handling.

This is accomplished by a flexible configuration that defines how the firewall should be built up.
While DFW is running, Docker container events will be monitored and the rules rebuilt when necessary.

One of the key-features of DFW (and DFWFW before it) is to not require the running containers to publish their ports on the host (à la `docker container run --publish 80:8080`), but rather use the network-address translation (NAT) features of the host-firewall to forward packets directly to the port in the container.<sup>[1](#fn-1)</sup>

DFW supports the following firewall backends:

* iptables
* nftables

You can choose the one that works best for you.<sup>[2](#fn-2)</sup>

<sub>
<sup><a name="fn-1"></a>1</sup>
This only applies if you use IPv4 on your host.
If you want to have IPv6-support, you still need to publish the ports.
See [IPv6 support](#configuration-ipv6) for more information.
</sub>
<br>
<sub>
<sup><a name="fn-2"></a>2</sup>
Please make sure to not mix firewall-backends: if you are already using one on your host, do not use the other one with DFW.
</sub>

[dfwfw-github]: https://github.com/irsl/dfwfw

### <a name="overview-example"></a> Example

Assume that you want to run a reverse proxy in Docker that should proxy traffic to a web-application that is also running in Docker.
With the regular tools provided by Docker you would simply host-bind the port, put the two Docker containers on the same Docker network and would have a working solution.

While this works quite well, having Docker handling the firewall rules has a few potential drawbacks:

1. Traffic to host-mounted ports is not restricted by default.

    While this usually is the desired behaviour, it might hurt you if you just want to launch a service and test it locally.<sup>[3](#fn-3)</sup>

    With DFW you have to be explicit: if you want your service to be reachable, you have to configure exactly which container should be reachable from where.
    While this does incur an upfront cost in terms of effort, it can reward you afterwards by ensuring you don't accidentally expose a service you didn't intend to expose.

2. Traffic between containers on the same Docker network is not restricted.

    Again: most of the time this is the desired behaviour.
    When it isn't though, Docker does not give you the tools to restrict this traffic.

    DFW allows you to configure _exactly_ how you want containers to be able to communicate with each other, both in the same Docker network and across Docker networks.

    In the example above we want the reverse proxy to communicate with the web-application, but the web-application should not be able to initiate a connection to the reverse proxy.
    DFW allows you to implement this scenario.

If you have not encountered the drawbacks described above and are happy with the features provided by Docker, you might not need DFW.
But if you have, or are simply interested in trying DFW out, take a look at the [reverse proxy example][example-reverseproxy] which will work you through the proposed example.

<sub>
<sup><a name="fn-3"></a>3</sup>
You can of course bind the port to `127.0.0.1`, but you have to be explicit about that, which is easy to forget.
</sub>

[example-reverseproxy]: https://github.com/pitkley/dfw/tree/main/examples/reverseproxy

## <a name="gettingstarted"></a> Getting started

If you are already a user of DFW and are looking to upgrade to a newer version, consult the matching migration documentation:

* [Migrating from DFW 1.x to 1.2][migration-v1.x-to-v1.2]
* [Migrating from DFW 0.x to 1.2][migration-v0.x-to-v1.2]
* ~~[Migrating from DFW 0.x to 1.0][migration-v0.x-to-v1.0]~~

If you are starting fresh, the first step is to decide on a firewall backend:

* nftables

    nftables can be seen as a newer generation of iptables, and it will replace iptables in most Linux distributions at some point.
    (It already is the default in e.g. Debian 10 Buster.)

    If you are starting fresh on a host where you have not used either backend yet, nftables is the suggested backend.

* iptables

    While iptables is the older netfilter implementation, it is still a valid firewall-backend and still finds extensive use across many distributions.

    If you are already using iptables and have a configuration that you don't want to re-do, feel free to use the iptables backend with DFW.

Once you have decided which backend you want to use, please consult the backend-specific documentation on how to proceed further:

* [nftables][docs-nftables]
* [iptables][docs-iptables]

[migration-v0.x-to-v1.0]: https://github.com/pitkley/dfw/blob/main/docs/migration/v0.x-to-v1.0.md
[migration-v0.x-to-v1.2]: https://github.com/pitkley/dfw/blob/main/docs/migration/v0.x-to-v1.2.md
[migration-v1.x-to-v1.2]: https://github.com/pitkley/dfw/blob/main/docs/migration/v1.x-to-v1.2.md
[docs-nftables]: https://github.com/pitkley/dfw/blob/main/docs/GETTING-STARTED-nftables.md
[docs-iptables]: https://github.com/pitkley/dfw/blob/main/docs/GETTING-STARTED-iptables.md

## <a name="configuration"></a> Configuration

The general configuration happens across six categories:

* `global_defaults`

    This category defines global, default values to be used by DFW and the other categories.

* `backend_defaults`

    This category defines configuration values that are specific to the firewall-backend used.

* `container_to_container`

    This controls the communication between containers and across [Docker networks][docker-networks].

* `container_to_wider_world`

    This controls if and how containers may access the wider world, i.e. what they can communicate across the `OUTPUT` chain on the host.

* `container_to_host`

    To restrict or allow access to the host, this section is used.

* `wider_world_to_container`

    This controls how the wider world, i.e. whatever comes in through the `INPUT` chain on the host, can communicate with a container or a Docker network.

* `container_dnat`

    This category allows you to define specific rules for destination network address translation, even or especially across Docker networks.

**See the [examples][examples] and [configuration types][types.rs] for detailed descriptions and examples of every configuration section.**

[docker-networks]: https://docs.docker.com/engine/userguide/networking/
[examples]: https://github.com/pitkley/dfw/tree/main/examples
[types.rs]: https://dfw.rs/latest/dfw/types/index.html

## <a name="ipv6support"></a> IPv6 support

If you make a container publicly available, DFW will use "destination NATting" and "masquerading" to redirect incoming packets to the correct internal IP of the container, and then correctly redirect the reponses back to the original requester.
Every default installation of Docker does _not_ assign private IPv6 addresses to networks and containers, it only assigns private IPv4s.

Generally there is also no need for private IPv6 addresses: Docker uses a proxy-binary when host-binding a container-port to perform the translation of traffic from the host to the container.
This host-binding is compatible with both IPv4 and IPv6, which means internally a single IPv4 is sufficient.

As mentioned, DFW does work differently: since it uses NAT to manage traffic, it effectively would have to translate incoming packets from IPv6 to IPv4 and the responses from IPv4 to IPv6, something that is not supported by nftables and iptables.

The consequence of this is that if you want your services to be reachable via IPv6, you have to ensure the following things:

1. You _have to_ publish the ports of the containers you want to be able to reach on your host through the Docker-integrated run-option `--publish`.

    The host-port you select here is the one under which it will be reachable publicly later, i.e. if you want your webserver to be reachable from host-ports 80 and 443, you need to publish the container ports under 80 and 443.

2. In your wider-world-to-container rule, the host-port part of your exposed port _must match_ the port you published the container ports under (although it doesn't have to match the container-port itself).

    As part of the wider-world-to-container rule DFW will create the firewall-rules necessary for the host-bound ports to be reachable via IPv6.
    For this to work the ports need to match the ports you have selected when publishing the container-ports.

    (If you are having trouble, make sure you don't have `expose_via_ipv6` set to `false` in your wider-world-to-container rule.)

### <a name="ipv6support-example"></a> Example: webserver reachable via IPv6

Let's assume you want to run a webserver as a Docker container and want ports 80 for HTTP and 443 for HTTPS on your host to forward to this container.
The container you use internally uses ports 8080 and 8443 for HTTP and HTTPS respectively.

The following is how you have to configure the container:

```
$ docker run \
    --name "your_container" \
    --network "your_network" \
    --publish 80:8080 \
    --publish 443:8443 \
    ...
```

This is how you'd configure your rule:

```toml
[[wider_world_to_container.rules]]
network = "your_network"
dst_container = "your_container"
expose_port = [
    "80:8080",
    "443:8443",
]
```

The result of this is that your container will be reachable from the host-ports 80 and 443, from both IPv4 and IPv6.

## <a name="supporteddockerversions"></a> Supported Docker versions

At least Docker 1.13.0 is required.

DFW is continuously and automatically tested with the following stable Docker versions (using the latest patch-version each):

* `19.03`
* `18.09`
* `18.06`
* `18.03`
* `17.12`
* `17.09`
* `17.07`
* `17.06`
* `1.13`

## <a name="versionbumppolicy"></a> Version bump policy

In general, the versioning scheme for DFW follows the semantic versioning guidelines:

* The patch version is bumped when backwards compatible fixes are made (this includes updates to dependencies).
* The minor version is bumped when new features are introduced, but backwards compatibility is retained.
* The major version is bumped when a backwards incompatible change was made.

Special cases:

* A bump in the minimum supported Rust version (MSRV), which for DFW currently is 1.45.2, will be done in minor version updates (i.e. they do not require a major version bump).
* DFW is available both as a binary for direct use and as a library on [crates.io](https://crates.io/crates/dfw).

    The target audience of DFW are the users of the binary, and support for the library's public API is only provided on a best-effort basis.

    Thus, changes that break the API of the library will be done in minor version updates, i.e. consumers of the library might have to expect breaking changes in non-major releases.

## <a name="license"></a> License

DFW is licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### <a name="license-contribution"></a> Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in DFW by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
