# Changelog

<!-- next-header -->

## Unreleased

* Reintegrate the iptables-backend.
* Make exposing containers via IPv6 configurable.
* Ensure consistent behaviour regardless of whether `[global_defaults]` has been specified or not.
* Don't exit DFW if there are no containers running ([#243], thanks to @Georgiy-Tugai).

<sub>Internal changes: dependency updates, move CI entirely to GitHub Actions.</sub>

[#243](https://github.com/pitkley/dfw/pull/243)

## 1.1.0 - Bugfix, dependency updates (c9dc9ba)

* Fix missing rule-validation causing incorrect rules to be created (#166, add063).
* Fix logic that applied a too coarse rule (#166, e4fb869).

<sub>Internal changes: dependency updates, upgraded shiplift from 0.3 to 0.6.</sub>

## 1.0.1 - Bugfixes, dependency updates (ebfe872)

* Fix source-CIDR-filtering for wider-world-to-container rules.

<sub>Internal changes: dependency updates.</sub>

## 1.0.0 - Goodbye iptables, hello nftables; IPv6 support (1913447)

* Replaced all iptables-backends by an nftables backend.
* Added IPv6 support.

## 0.5.1 - Allow source-IP restrictions on WWTC rules (998d36c)

* You can now specify IP-ranges in wider-world-to-container rules, allowing you to restrict the source from which a service can be reached.

<sub>Internal changes: dependency updates.</sub>

## 0.5.0 - iptables-restore fixes (eb71bcd)

### Changes to the `dfw` binary

* Added argument `--log-level` which allows you to specify the verbosity of DFW's logging.

### Changes to the `dfw` library

* The `iptables-restore` backend now acts flushing (033d27c)
* Removed the unnecessary `IPTablesProxy` struct (4e62ff2)

<sub>Internal changes: updated GitLab CI config, updated dependencies, updated tested Docker versions.</sub>

## 0.4.0 - iptables-restore backend (9bd6027)

* Added argument `--iptables-backend` which allows selection of what backend to use:
    * `iptables` *(default)*
    * `iptablesrestore`
    * `iptablesdummy` *(same as `--dry-run`)*
* Added `iptables-restore` as a new backend
* Added [example configurations](examples/)
* Extended/updated list of Docker versions tested

<sub>Internal changes: updated GitLab CI config, cleaned up macros used, updated dependencies.</sub>

## 0.3.0 - First release on crates.io (32d3a51)

* Only process running containers by default.

## 0.2.3 (e7af9c3)

* Fix DNAT rule generation.

## 0.2.2 (d5e5d95)

* Added dry-run option to CLI.
* Added option to only process running containers.

<sub>Internal changes: split into binary and library, add testing infrastructure to perform integration tests against Docker, add a lot of unit tests.</sub>

## 0.2.1 (122e083)

* Small internal changes.

## 0.2.0 (babae7c)

* Implement further features.
* Refactor configuration types.
* Extend documentation.
* Extend logging.

## 0.1.4 (3e2b55a)

* Add missing licenses.

## 0.1.3 (1411336)

* Allow bursting of events.
* Refactor internal rule generation code.

## 0.1.2 (482bcb2)

* Add missing `iptables`/`ip6tables` binaries to Docker image.

## 0.1.1 (1ac7217)

* Add Docker event-monitoring.

## 0.1.0 - Initial release (74b3087)
