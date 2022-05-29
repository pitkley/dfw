# Getting started - iptables firewall backend

## <a name="preparingyourhost"></a> Preparing your host

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

* [ ] Migrate any custom iptables-rules you have to DFW.

    DFW is only able to work with iptables if it manages the entire firewall ruleset.
    To still enable you to have custom rules, you can specify the `backend_defaults.initialization.{v4,v6}` keys in your configuration.

    The configuration-keys allow you to add rules to any valid [table][iptables-man-tables].
    The only thing important is that the rules are valid iptables-syntax.

    **Example:**

    ```toml
    [backend_defaults.initialization.v4]
    filter = [
        "-A INPUT -p tcp --dport 22 -j ACCEPT"
    ]
    nat = [
        # Any rule you might want to add to the NAT-table...
    ]
    [backend_defaults.initialization.v6]
    filter = [
        "-A INPUT -p tcp --dport 22 -j ACCEPT"
    ]
    ```

    [iptables-man-tables]: https://manpages.debian.org/unstable/iptables/iptables.8.en.html#TABLES

## <a name="configuration"></a> Configuration

The general configuration happens across six categories:

* `global_defaults`

    This category defines global, default values to be used by DFW and the other categories.

    [Field reference.](https://dfw.rs/1.2.1/dfw/types/struct.GlobalDefaults.html)

* `backend_defaults`

    This category defines configuration values that are specific to the firewall-backend used.

    [Field reference for `iptables`.](https://dfw.rs/1.2.1/dfw/iptables/types/struct.Defaults.html)

* `container_to_container`

    This controls the communication between containers and across [Docker networks][docker-networks].

    [Field reference.](https://dfw.rs/1.2.1/dfw/types/struct.ContainerToContainer.html)

* `container_to_wider_world`

    This controls if and how containers may access the wider world, i.e. what they can communicate across the `OUTPUT` chain on the host.

    [Field reference.](https://dfw.rs/1.2.1/dfw/types/struct.ContainerToWiderWorld.html)

* `container_to_host`

    To restrict or allow access to the host, this section is used.

    [Field reference.](https://dfw.rs/1.2.1/dfw/types/struct.ContainerToHost.html)

* `wider_world_to_container`

    This controls how the wider world, i.e. whatever comes in through the `INPUT` chain on the host, can communicate with a container or a Docker network.

    [Field reference.](https://dfw.rs/1.2.1/dfw/types/struct.WiderWorldToContainer.html)

* `container_dnat`

    This category allows you to define specific rules for destination network address translation, even or especially across Docker networks.

    [Field reference.](https://dfw.rs/1.2.1/dfw/types/struct.ContainerDNAT.html)

**See the [examples][examples] and [configuration types][types.rs] for detailed descriptions and examples of every configuration section.**

[docker-networks]: https://docs.docker.com/engine/userguide/networking/
[examples]: https://github.com/pitkley/dfw/tree/main/examples
[types.rs]: https://dfw.rs/1.2.1/dfw/types/index.html

## <a name="runningdfw"></a> Running DFW

You have a few options of running DFW:

* Using the official Docker image *(preferred!)*.
* Using a pre-built binary directly on your host.
* Install DFW through crates.io.
* Build from source.

### Using the official Docker image

```console
$ docker pull pitkley/dfw:1.2.1
$ docker run -d \
      --name=dfw \
      -v /var/run/docker.sock:/var/run/docker.sock:ro \
      -v /path/to/your/config:/config \
      --net host --cap-add=NET_ADMIN \
      pitkley/dfw:1.2.1 --firewall-backend iptables --config-path /config
```

This will download a lightweight image, coming in at under 10 MB, and subsequently run it using your configuration.
The image supports multiple architectures: `amd64`, `arm64`, `armv7` (specifically `armhf`).

Please note that you can also pull the image from the GitHub container registry, GHCR, if you want to avoid potential pull-limitations Docker Hub has put in place:

```console
$ docker pull ghcr.io/pitkley/dfw:1.2.1
$ docker run ... ghcr.io/pitkley/dfw:1.2.1 ...
```

### Using a pre-built binary directly on your host.

You can retrieve the latest pre-built binary from the GitHub releases page:

* [Release page](https://github.com/pitkley/dfw/releases/latest)
* [Direct download](https://github.com/pitkley/dfw/releases/latest/download/dfw-x86_64-unknown-linux-musl) (static Linux x86_64 binary, no further dependencies required)

### Install DFW through crates.io.

For this you need to first [install Rust][rustlang-install] and then install DFW using cargo:

```console
$ cargo install dfw
$ dfw --help
dfw 1.2.1
Docker Firewall Framework, in Rust
...
```
### Build from source.

For this you need to first [install Rust][rustlang-install].
You can then check out the repository and build the binary:

```console
$ git checkout https://github.com/pitkley/dfw
$ cd dfw/
$ cargo build --release
$ target/release/dfw
Docker Firewall Framework, in Rust
...
```

[rustlang-install]: https://www.rust-lang.org/tools/install
