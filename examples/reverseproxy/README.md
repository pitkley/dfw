# Example: reverse proxy

In this example we'll run a reverse proxy in front of a simple web-application, exposing the reverse proxy on the host and allowing communication from the reverse proxy to the web-container on path `/foo`.

The [`docker-compose.yml`](docker-compose.yml) can be used to launch the services by running `docker-compose --project-name dfwexample up`:

```yaml
version: '2'
services:
    reverseproxy:
        # We use Traefik as our reverse proxy for this example, mainly because
        # the configuration is self-contained through the use of Docker labels.
        image: traefik:2.2
        volumes:
        - /var/run/docker.sock:/var/run/docker.sock:ro
        command:
        # We configure Traefik to automatically discover Docker containers for
        # us, although they shouldn't be proxied by default.
        - "--providers.docker=true"
        - "--providers.docker.exposedbydefault=false"

    webserver:
        # We use a simple whoami image for our webservers.
        image: containous/whoami:latest
        labels:
        # By defining the traefik label below, we tell Traefik to proxy for this
        # container.
        - traefik.enable=true
```

Although the containers will launch fine, you'll notice that reaching any of the containers is not yet possible, since no ports have been bound to the host.
This is where DFW comes in: we'll be able to provide DFW with a configuration that determines how the containers above should be exposed, without having to host-bind the ports.

We will be using [the following configuration](dfw.toml):

```toml
[global_defaults]
# First we define the external network interfaces we want to listen to, i.e.
# the network-interfaces from which traffic should be allowed. You can provide
# a single interface with a simple string, or multiple by providing a list.
external_network_interfaces = "eth0"
#                              ^- INSERT YOUR DESIRED NETWORK INTERFACE HERE

# Next we define the container-to-container (C2C) communication, i.e. if and
# how containers are allowed to communicate amongst themselves.
[container_to_container]
# We first set a default policy for C2C communication which will determine if
# containers will be allowed to communicate with other containers in the same
# or other networks by default, or whether no traffic should be allowed. We
# will drop all traffic by default and add an exception through a rule below.
default_policy = "drop"

# Now we define a rule to allow traffic between our containers. For our example
# we want the reverse proxy to be able to talk to the webservers. We will thus
# add a rule to allow this traffic.
[[container_to_container.rules]]
network = "dfwexample_default"
src_container = "dfwexample_reverseproxy_1"
verdict = "accept"

# Note that we have only defined a network and a source-container. We could
# have also defined a specific destination container if we wanted a finer, more
# restrictive rule:
#
# [[container_to_container.rules]]
# network = "dfwexample_default"
# src_container = "dfwexample_reverseproxy_1"
# dst_container = "dfwexample_foo_1"
# verdict = "accept"

# At this point the reverse proxy can communicate with the webservers, but we
# can't communicate with the reverse proxy yet. To enable this we use the
# wider-world-to-container (WW2C) configuration.
[wider_world_to_container]
# We'll define a rule that will route traffic that reaches the host on port 80
# to the reverse proxy on port 80.
[[wider_world_to_container.rules]]
network = "dfwexample_default"
dst_container = "dfwexample_reverseproxy_1"
expose_port = 80

# Note: the host-port, 80 in this case, will not be bound! DFW performs network
# address translation on the firewall level which will not bind an address/the
# port. This means that if you have a host-service on a port that DFW also
# manages, you will not get an error and the host-bound service will not be
# reachable anymore.
```

With this configuration saved under e.g. `example.toml`, you can now start DFW and have it set up your firewall:

```shell
docker run --rm \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v dfw.toml:/config/dfw.toml \
    --net host --cap-add=NET_ADMIN \
    pitkley/dfw:1.2.1 --config-file /config/dfw.toml
```

(*Please note:* DFW will use the nftables firewall backend by default. If you want to use iptables, provide the `--firewall-backend iptables` command-line argument.)

**Congratulations!**
You have successfully set up DFW to route traffic to a container and between containers with full control.
