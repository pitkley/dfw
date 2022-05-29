# Troubleshooting

This document collects known problems that might occur when using DFW, and instructions on how to fix them.

If you are experiencing issues with DFW that you don't find represented here, feel free to [open a GitHub issue describing your problem](https://github.com/pitkley/dfw/issues/new).

---

* [Can't filter container-to-container traffic in same network](#cant-filter-container-to-container-traffic-in-same-network)
* [modprobe error when running in Docker](#modprobe-error-when-running-in-docker)
* [set up rule failed, `DOCKER_OUTPUT`/`DOCKER_POSTROUTING`](#set-up-rule-failed-docker_outputdocker_postrouting)

---

## Can't filter container-to-container traffic in same network

Depending on how your host is configured, traffic whose origin and destination interface are the same Docker network (i.e. the same *bridge*) is not filtered by the kernel netfilter module.
This means that both the default policy and any rules specified in the `[container_to_container]` section  are not applied for traffic between containers that are on the same Docker network, but instead only for traffic that traverses two distinct Docker networks/bridges.

If your kernel has the `br_netfilter` kernel-module available, you can set the `sysctl net.bridge.bridge-nf-call-iptables` to `1` to have the netfilter-module act on traffic within the same bridge, too. You can set this value temporarily like this:

```
sysctl net.bridge.bridge-nf-call-iptables=1
```

To permanently set this configuration, take a look at `man sysctl.d` and `man sysctl.conf`.

See also:

- [Issue #568](https://github.com/pitkley/dfw/issues/568)
- [`ContainerToContainer::default_policy` reference](https://dfw.rs/1.2.1/dfw/types/struct.ContainerToContainer.html#filtering-traffic-within-the-same-bridge)

## modprobe error when running in Docker

```
ip6tables-restore failed: 'modprobe: can't change directory to '/lib/modules': No such file or directory
ip6tables-restore v1.8.4 (legacy): ip6tables-restore: unable to initialize table 'filter'

Error occurred at line: 1
Try `ip6tables-restore -h' or 'ip6tables-restore --help' for more information.'
```

This error can occur if DFW is configured to use a firewall-backend like iptables on a host where the kernel-modules necessary for that backend to function are not loaded.

The applications used by DFW to manage the rules (`iptables-restore`, `ip6tables-restore`, `nft`) will try to load the modules automatically if necessary, but will fail because the Docker container by default is not allowed to load the modules.

If you want DFW running in Docker to be able to automatically load the kernel modules, you can start DFW as follows:

```
docker run -d \
    --name=dfw \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v /lib/modules:/lib/modules:ro \
    -v /path/to/your/config:/config \
    --net host --cap-add=NET_ADMIN --cap-add=SYS_MODULE \
    pitkley/dfw:latest --config-path /config ...
```

The important additions over the default run-command are:

* `-v /lib/modules:/lib/modules:ro`

    This mounts the kernel-modules available on the host into the Docker container (as read-only).

* `--cap-add=SYS_MODULE`

    This enables the Docker container to manage the host's kernel modules.

## set up rule failed, `DOCKER_OUTPUT`/`DOCKER_POSTROUTING`

```
set up rule failed, [-t nat -I DOCKER_OUTPUT -d 127.0.0.11 -p udp --dport 53 -j DNAT --to-destination 127.0.0.11:53982]
set up rule failed, [-t nat -I DOCKER_POSTROUTING -s 127.0.0.11 -p udp --sport 53982 -j SNAT --to-source :53]
set up rule failed, [-t nat -I DOCKER_OUTPUT -d 127.0.0.11 -p tcp --dport 53 -j DNAT --to-destination 127.0.0.11:32987]
set up rule failed, [-t nat -I DOCKER_POSTROUTING -s 127.0.0.11 -p tcp --sport 32987 -j SNAT --to-source :53]
```

If you have DNS resolution errors and are seeing errors like above, your Kernel might be missing required modules or may be misconfigured.
You can find detailed information about this in [issue #370].

[issue #370]: https://github.com/pitkley/dfw/issues/370#issuecomment-766272308
