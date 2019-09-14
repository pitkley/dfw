# Migrating from DFW v0.x to v1.0 (iptables to nftables)

With DFW v1.0 the iptables-based backends where removed and replaced in favour of an nftables-based backend.
While nftables brings many advantages, it also bears some challenges which are described in the following sections.

-----

1. [Migrating your host from iptables to nftables](#migrating-host)
2. [Migrating your pre-v1.0 DFW configuration](#migrating-config)
    1. [New keys](#migrating-config-newkeys)
    2. [Breaking changes](#migrating-config-breakingchanges)
    3. [Backwards-compatible changes](#migrating-config-backwardscompatiblechanges)

-----

## <a name="migrating-host"></a>Migrating your host from iptables to nftables

Migrating your host from iptables to nftables is [described in the nftables wiki][nftableswiki-movingfromiptables].
The rough outline is as follows:

1. Export your iptables rules (`iptables-save`).
2. Translate them into nftables rules (`iptables-restore-translate`).
3. Import them into nftables (`nft -f`).

One point to add to this: most distributions include the file `/etc/nftables.conf` as part of their nftables userspace package, which will be automatically loaded on system-boot through the systemd-service `nftables`.
This is an easy way to add your pre-existing (or new) rules to the default nftables-chains and have them be loaded whenever you boot.

[nftableswiki-movingfromiptables]: https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables

For more general information on nftables, see the following resources:

* [nftables wiki][nftableswiki]
* [nftables - Debian Wiki][debianwiki-nftables]

[nftableswiki]: https://wiki.nftables.org/wiki-nftables/index.php/Main_Page
[debianwiki-nftables]: https://wiki.debian.org/nftables

## <a name="migrating-config"></a>Migrating your pre-v1.0 DFW configuration

The switch to nftables required changes to the configuration-structure of DFW.
Some changes are new, others are breaking and require you to adapt your configuration, and some are backwards compatible but should be applied.

**Short summary**, here is what you have to do to update your configuration:

1. Add/configure the `defaults.custom_tables` setting.
2. Replace the `initialization.v4` and `initialization.v6` sections by the `initialization.rules` key, changing the rules to be nft-compatible.
3. Change any `filter`-fields in your container-to-container, container-to-wider-world, or container-to-host rules to `matches` and update it to be nft-compatible.

For full details see the following sections.

### <a name="migrating-config-newkeys"></a>New keys

* The key `custom_tables` was added to the `defaults` section.

    For DFW to support custom nftables tables to exist in parallel, it needs to hook into the chains in these pre-existing tables.
    The `custom_tables` key is used for the user to provide the name(s) and chains of their pre-existing tables.

    (One of the main advantages of nftables is that multiple tables can exist, which allows DFW to manage its rules in a completely separate namespace from the users rules.
    For this to fully work the mentioned hooks are necessary.)

    On a default nftables installation (verified on various Linux distributions) the `filter` table will be created, containing the `input` and `forward` chains.
    The following configuration would be valid for this setup:

    ```toml
    [defaults]
    custom_tables = { name = "filter", chains = ["input", "forward"] }
    ```

### <a name="migrating-config-breakingchanges"></a>Breaking changes

* The `initialization` section no longer has the `v4` and `v6` subsections.

    Not only are they obsolete through the `inet`-tables supported by nftables, they were allowed to contain iptables-compatible rules which are strictly incompatible with nftables commands.

    The sections were replaced by the `rules` key, a list of commands that are executed using `nft`.

    **Example, before:**

    ```toml
    [initialization]
    [initialization.v4]
    filter = [
        "-A INPUT -p tcp --dport 22 -j ACCEPT"
    ]
    [initialization.v6]
    filter = [
        "-A INPUT -p tcp --dport 22 -j ACCEPT"
    ]
    ```

    **After:**

    ```toml
    [initialization]
    rules = [
        "add rule inet filter input tcp dport 22 accept"
    ]
    ```

* The container-to-container, container-to-wider-world, and container-to-host rules no longer have the `filter` field (now called `matches`).

    The `filter` field was used to further restrict the rules, e.g. to restrict container-to-container communication to certain ports.
    The `filter` argument contained iptables-compatible rule-statements, which are strictly incompatible with nftables.

    For nftables the field is called `matches` and expects valid nft-statements.

    **Example, before:**

    ```toml
    [[container_to_container.rules]]
    network = "reverseproxy_network"
    src_container = "my_reverseproxy"
    dst_container = "my_webserver"
    filter = "-p tcp --dport 8080"
    action = "ACCEPT"
    ```

    **After:**

    ```toml
    [[container_to_container.rules]]
    network = "reverseproxy_network"
    src_container = "my_reverseproxy"
    dst_container = "my_webserver"
    matches = "tcp dport 8080"
    verdict = "accept"
    ```

### <a name="migrating-config-backwardscompatiblechanges"></a>Backwards-compatible changes

* The container-to-container, container-to-wider-world, and container-to-host rules renamed the `action` field to `verdict`.

    nftables no longer uses the word "action" to describe the final result that will be applied to a network-packet, but rather "verdict".
    Further the representation of the verdict itself is now in all lowercase, rather than all uppercase (e.g. `ACCEPT` -> `accept`).

    DFW follows both those changes, although it is fully backwards-compatible to both the key used and values provided.
    This means that your rules with `action = "ACCEPT"` continue to work the same way, even though `verdict = "accept"` is the new configuration.

    **Example, before:**

    ```toml
    [[container_to_container.rules]]
    network = "common_network"
    src_container = "container_a"
    dst_container = "container_b"
    action = "ACCEPT"
    ```

    **After:**

    ```toml
    [[container_to_container.rules]]
    network = "common_network"
    src_container = "container_a"
    dst_container = "container_b"
    verdict = "accept"
    ```

* The container-to-container, container-to-wider-world, and container-to-host `default_policy`-field values should now be in lowercase.

    nftables no longer uses the uppercase variants of chain-verdicts, they are now all lowercase (e.g. `ACCEPT` -> `accept`).

    DFW follows this change, although it is fully backwards-compatible to the value provided.
    This means that `default_policy = "ACCEPT"` continues to work the same way, even though `default_policy = "accept"` is the new configuration.

    **Example, before:**

    ```toml
    [container_to_container]
    default_policy = "ACCEPT"
    ```

    **After:**

    ```toml
    [container_to_container]
    default_policy = "accept"
    ```
