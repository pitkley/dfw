# Full, single-file configuration example

This directory contains a DFW configuration file `dfw.toml`.
The file shows examples for most (if not all) possible configurations you might need, with additional explanations for each of the examples.
If you are unsure about any of the explanations, be sure to also check out the [documentation on the internal types](https://docs.rs/dfw/*/dfw/types/index.html) that are configured through this TOML file.
Each of the sections in this file matches to a struct under the same name, and every struct field contains some documentation that might help you out.

To use this configuration, start DFW in the following way:

```console
# dfw --config-file dfw.toml
```

If you are using the docker image, you can use the following command:

```console
# docker run -d \
    --name=dfw \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v $PWD/dfw.toml:/config/dfw.toml \
    --net host --cap-add=NET_ADMIN \
    pitkley/dfw:latest \
        --config-file /config/dfw.toml
```

**Note:** While the configuration itself is valid, it is not meaningful and you'll have to adapt it to your needs.
Processing of the configuration by DFW might fail due to the networks and containers specified missing.

