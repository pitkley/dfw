# Regression test for GitHub issue 265

|Issue:|[#265]|
|-|-|
|Reporter:|@pitkley|
|Summary:|DFW 1.2.0-rc.1 did not handle the fields `global_defaults.initialization` and `global_defaults.custom_tables` that should have been retained for backwards-compatibility if the `backend_defaults`-key was not specified.|

[#265]: https://github.com/pitkley/dfw/issues/265

## Tests added

* [01/](01/) verifies that the `global_defaults.custom_tables` field is correctly evaluated if `backend_defaults.custom_tables` has not been specified.
* [02/](02/) verifies that the `initialization` field is correctly evaluated if `backend_defaults.initialization` has not been specified.
* [03/](03/) verifies that the `initialization` field is correctly evaluated if `backend_defaults.initialization` has not been specified *but `backend_defaults` itself has*.
