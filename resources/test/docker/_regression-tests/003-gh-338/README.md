# Regression test for GitHub pull request 338

|Pull request:|[#338]|
|-|-|
|Reporter:|@pitkley|
|Summary:|DFW 1.2.0 and below did not handle the `host_port` field of the `expose_port` field for `wider_world_to_container.rules` correctly. It still used the `container_port`, leading to false or conflicting firewall rules.|

[#338]: https://github.com/pitkley/dfw/pull/338

## Tests added

* [01/](01/) verifies that the `host_port` is used correctly if it differs from the `container_port`.
