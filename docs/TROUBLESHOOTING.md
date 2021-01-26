# Troubleshooting

This document collects known problems that might occur when using DFW, and instructions on how to fix them.

If you are experiencing issues with DFW that you don't find represented here, feel free to [open a GitHub issue describing your problem](https://github.com/pitkley/dfw/issues/new).

---

* [modprobe error when running in Docker](#modprobe-error-when-running-in-docker)

---

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
