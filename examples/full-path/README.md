# Full, multi-file/path configuration example

This directory contains a `conf.d` subdirectory with multiple TOML files, each
configuring some aspect of DFW. When DFW starts, it will take all the files,
concatenate them and then load them as if they were a single file. The
concatenation-order of the files is not guaranteed, but since each section has
to be a fully specified table anyway, the order does not affect the resulting
configuration.

(The configuration displayed in this example is identical to
[`full-simple-file`](../full-simple-file), it is simply split up across
multiple files to demonstrate this feature.)

The files show examples for most (if not all) possible configurations you might
need, with additional explanations for each of the examples. If you are unsure
about any of the explanations, be sure to also check out the [documentation on
the internal types](https://docs.rs/dfw/*/dfw/types/index.html) that are
configured through this TOML file. Each of the sections in this file matches to
a struct under the same name, and every struct field contains some
documentation that might help you out.

To use this configuration, start DFW in the following way:

```console
# dfw --config-path conf.d
```

If you are using the docker image, you can use the following command:

```console
# docker run -d \
    --name=dfw \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    -v $PWD/conf.d:/config \
    --net host --cap-add=NET_ADMIN \
    pitkley/dfw \
        --config-path /config
```

**Note:** While the resulting configuration itself is valid, it is not
meaningful and you'll have to adapt it to your needs. Processing of the
configuration by DFW might fail due to the networks and containers specified
missing.

