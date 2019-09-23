# DFW - Docker Firewall Framework in Rust

## Breaking change in v1.0 (iptables replaced by nftables)

Starting with version 1.0, DFW switched to using the [nftables] backend internally, no longer suppporting iptables-based installations.
There were multiple reasons for this decision:

* Rule management is overall cleaner.
* All major distributions support installing nftables.
* Some distributions, like Debian 10 (Buster), switch to nftables being the default on a fresh installation.

This switch brings a couple of challenges with it to users who have already used iptables.
First, one has to get accustomed to the new syntax and concepts. Following are a couple of good resources for getting your feet wet:

* [Moving from iptables to nftables - nftables wiki][nftableswiki-movingfromiptables]
* [nftables - Debian Wiki][debianwiki-nftables]

In general the [nftables wiki][nftableswiki] is a great resource for everything nftables.
The man-page of the `nft`-tool is also very insightful.

A second challenge is that existing DFW configurations have to be slightly modified to work with version 1.0.
See the [migration documentation][migration-v0.x-to-v1.0].

**If you don't want to switch to nftables but want to keep using DFW** take a look at the `iptables` branch in this repository.
It is the last working state of DFW from before the nftables-switch.
While it will not receive any new features, the dependencies used will be kept up-to-date on a best-effort basis to ensure any security-fixes will be applied.
For further information, look at the README in the `iptables` branch, but in short: use the `pitkley/dfw:iptables` Docker image instead of `pitkley/dfw:latest`.

[nftables]: https://netfilter.org/projects/nftables/
[nftableswiki]: https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
[nftableswiki-movingfromiptables]: https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables
[debianwiki-nftables]: https://wiki.debian.org/nftables
[migration-v0.x-to-v1.0]: https://github.com/pitkley/dfw/blob/master/MIGRATION-v0.x-to-v1.0.md

-----

1. [Overview](#overview)
2. [Installation](#installation)
    1. [Preparing your host](#installation-preparingyourhost)
    2. [Running DFW](#installation-runningdfw)
3. [Configuration](#configuration)
    1. [IPv6 support](#configuration-ipv6)
4. [Troubleshooting](#troubleshooting)

-----

## <a name="overview"></a> Overview

`dfw` is conceptually based on the [Docker Firewall Framework, `dfwfw`][dfwfw-github].
Its goal is to make firewall administration with Docker simpler, but also more extensive by trying to replace the Docker built-in firewall handling by direct interaction with iptables.

This is accomplished by a flexible configuration which defines how the firewall should be built up.
While DFW is running, Docker container events will be monitored and the rules rebuilt when necessary.

One of the key-features of DFW (and DFWFW before it) is to not require the running containers to publish their ports on the host (à la `docker container run --publish 80:8080`), but rather use the network-address translation (NAT) features of the host-firewall to forward packets directly to the port in the container.
_(Note: this only applies if you use IPv4 on your host.
If you want to have IPv6-support, you still need to publish the ports.
See [IPv6 support](#configuration-ipv6) for more information.)_

See [DFWFW's README][dfwfw-readme] for more insight.
Most of what you will read there will be applicable to DFW.

## <a name="installation"></a> Installation

### <a name="installation-preparingyourhost"></a> Preparing your host

* [ ] Have at least kernel 3.18

    The core of nftables is developed as part of the kernel.
    nftables has first been available in kernel 3.13, but support for one of the core features we use (masquerading) has only landed with kernel 3.18.

    You can check your kernel-version by executing `uname -r`:

    ```console
    $ uname -r
    4.15.0-58-generic
    ```

    Should your kernel-version be lower than 3.18, you have to check the documentation for your distribution on how to update it.

    (Having a recent 4.x-kernel is preferrable to profit from potential optimizations and bug-fixes.)

* [ ] Configure Docker daemon

    When you want DFW to manage your firewall, it is essential that you disable the iptables-features integrated in the Docker daemon.
    Probably the easiest way to do this is to modify (or create) the file `/etc/docker/daemon.json` and add the following contents:

    ```json
    {
        "iptables": false
    }
    ```

    Be sure to restart your Docker daemon afterwards.
    (You might also have to remove any rules the Docker-daemon might have already created in iptables.
    The easiest way to do this is to reboot your host.)

* [ ] Install nftables userspace utility `nft` *(optional when running DFW in Docker, but still recommended)*

    Installing the userspace utility for nftables, `nft`, is strictly necessary if you run the DFW-binary directly on your host, and overall recommended no matter how you run DFW.
    How to install `nft` depends on your distribution/package manager, but one of the following should work:

    * `apt install nftables` (for Debian, Ubuntu, ...)
    * `yum install nftables` (for RHEL, CentOS, ...)
    * `pacman -S nftables` (for Arch, Manjaro, ...)
    * `zypper install nftables` (for SLES, OpenSuse, ...)

* [ ] Migrate any custom iptables-rules you have to nftables *(if you haven't managed any iptables rules or are already using nftables, you can skip this step)*

    A description on how to migrate your iptables-rules [can be found in the nftables wiki][nftableswiki-movingfromiptables].
    The rough outline is as follows:

    1. Export your iptables rules (`iptables-save`).
    2. Translate them into nftables rules (`iptables-restore-translate`).
    3. Import them into nftables (`nft -f`).

    One point to add to this: most distributions include the file `/etc/nftables.conf` as part of their nftables userspace package, which will be automatically loaded on system-boot through the systemd-service `nftables`.
    This is an easy way to add your pre-existing (or new) rules to the default nftables-chains and have them be loaded whenever you boot.

    [nftableswiki-movingfromiptables]: https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables

* [ ] Prepare the default nftables-configuration (or the configuration you imported in the previous step)

    As mentioned in the previous step, most distributions include the file `/etc/nftables.conf` as their default nftables configuration when you install the `nft` utility.
    This file usually contains a very barebones ruleset, including the `input`, `forward` and `output` chains, all configured to accept all traffic (there might be no explicit policy, which equals `accept`).

    One suggestion here is to change the `input` and `forward` policies to `drop` packets that are not explicitly allowed, ensuring that nobody can access resources that you don't want to be public.
    **BE CAREFUL:** do not apply this change before you also added any rules you might require to e.g. access SSH on your host.
    The following is a simple example for what this configuration file can look like:

    ```norun
    #!/usr/sbin/nft -f

    flush ruleset

    table inet filter {
        chain input {
            type filter hook input priority 0; policy drop;
            tcp dport 22 accept
        }
        chain forward {
            type filter hook forward priority 0; policy drop;
        }
        chain output {
            type filter hook output priority 0; policy accept;
        }
    }
    ```

    This configuration specifically adds a rule to accept incoming connections on port 22.

    The `/etc/nftables.conf` configuration file can be loaded through various ways, here are some examples (all executed as `root` or through `sudo`):

    * ```systemctl reload nftables```
    * ```/etc/nftables.conf``` (the configuration itself can be executed)
    * ```nft -f /etc/nftables.conf```

    All three options lead to the same result: the entire ruleset will be discarded and subsequently filled with what you have configured.

### <a name="installation-runningdfw"></a> Running DFW

You have two general options of running DFW:

* Using the official Docker image *(preferred!)*.
* As a binary directly on your host.

#### Using the official Docker image

```console
$ docker pull pitkley/dfw:latest
$ docker run -d \
      --name=dfw \
      -v /var/run/docker.sock:/var/run/docker.sock:ro \
      -v /path/to/your/config:/config \
      --net host --cap-add=NET_ADMIN \
      pitkley/dfw:latest --config-path /config
```

This will download a lightweight image, coming in at about 7 MB, and subsequently run it using your configuration.

#### As a binary directly on your host

We currently do not provide any pre-built binaries (aside from the Docker image), so you will have to build the binary yourself.
For this you need to first [install Rust][rustlang-install] and then install DFW:

```console
$ cargo install dfw
$ dfw --help
dfw 1.0.0
Docker Firewall Framework, in Rust
...
```

[rustlang-install]: https://www.rust-lang.org/tools/install

## <a name="configuration"></a> Configuration

The general configuration happens across six categories:

* `defaults`

    This category defines global, default values to be used by DFW and the other categories.

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

One category which DFWFW covers that is not (yet) implemented in DFW is `container_internals`, that is configuring iptables rules within containers.

**See the [examples][examples] and [configuration types][types.rs] for detailed descriptions and examples of every configuration section.**

### <a name="configuration-ipv6"></a> IPv6 support

If you make a container publicly available, DFW will use "destination NATting" and "masquerading" to redirect incoming packets to the correct internal IP of the container, and then correctly redirect the reponses back to the original requester.
Every default installation of Docker does _not_ assign private IPv6 addresses to networks and containers, it only assigns private IPv4s.

Generally there is also no need for private IPv6 addresses: Docker uses a proxy-binary when host-binding a container-port to perform the translation of traffic from the host to the container.
This host-binding is compatible with both IPv4 and IPv6, which means internally a single IPv4 is sufficient.

As mentioned, DFW does work differently: since it uses NAT to manage traffic, it effectively would have to translate incoming packets from IPv6 to IPv4 and the responses from IPv4 to IPv6, something that nftables does not support.

The consequence of this is that if you want your services to be reachable via IPv6, you have to ensure the following things:

1. You _have to_ publish the ports of the containers you want to be able to reach on your host through the Docker-integrated run-option `--publish`.

    The host-port you select here is the one under which it will be reachable publicly later, i.e. if you want your webserver to be reachable from host-ports 80 and 443, you need to publish the container ports under 80 and 443.

2. In your wider-world-to-container rule, the host-port part of your exposed port _must match_ the port you published the container ports under.

    As part of the wider-world-to-container rule DFW will create the firewall-rules necessary for the host-bound ports to be reachable via IPv6.
    For this to work the ports need to match the ports you have selected when publishing the container-ports.

#### Example: webserver reachable via IPv6

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

## <a name="troubleshooting"></a> Troubleshooting

todo: describe managing of custom nftables table, re: priority

## <a name="supporteddockerversions"></a> Supported Docker versions

At least Docker 1.13.0 is required.

DFW has been successfully tested under the following stable Docker versions:

* `1.13.1`
* `17.03.3-ce`
* `17.06.2-ce`
* `17.07.0-ce`
* `17.09.1-ce`
* `17.12.1-ce`
* `18.03.1-ce`
* `18.06.1-ce`
* `18.09.7-ce`

## <a name="license"></a> License

DFW is licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### <a name="license-contribution"></a> Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in DFW by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[dfwfw-github]: https://github.com/irsl/dfwfw
[dfwfw-readme]: https://github.com/irsl/dfwfw/blob/master/README.md

[docker-networks]: https://docs.docker.com/engine/userguide/networking/

[examples]: https://github.com/pitkley/dfw/tree/master/examples
[types.rs]: https://docs.rs/dfw/*/dfw/types/index.html
