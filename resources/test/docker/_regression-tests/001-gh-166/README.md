# Regression test for GitHub issue 166

|Issue:|#166|
|-|-|
|Reporter:|@thielepaul|
|Summary:|DFW >=1.0.0,<1.1.0 did not fail if an unknown network or container was specified whereas DFW <1.0.0 did.|

## Tests added

* [01/](01/) verifies that DFW fails if both a non-existent network and container have been specified.
* [02/](02/) verifies that DFW fails if a existent network but a non-existent container have been specified.
* [03/](03/) verifies that DFW fails if a non-existent network but a existent container have been specified.
* [04/](04/) verifies that DFW succeeds if both network and container exist.
