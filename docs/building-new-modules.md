One way to think of Fedimint is as a framework for building federated applications with no single point of trust.

In order to build such an application, you need to fork the `fedimint` git repo. Create a new crate in the `modules` folder - you can use the [`fedimint-dummy-*`](https://github.com/fedimint/fedimint/tree/master/modules) crates as inspiration. Next `impl` two traits:

* [ServerModluePlugin](https://github.com/fedimint/fedimint/blob/c0651f88068b5818cb42a1d038d3b55d26b41e56/fedimint-api/src/module/mod.rs#L229-L360): defines how your module will interact with Fedimint consensus.
* [FederationModuleConfigGen](https://github.com/fedimint/fedimint/blob/99e5b50f1809b5d5d144dcfcde1dafd113e1c0fe/fedimint-api/src/module/mod.rs#L202-L227): defines how configuration for your module will be generated.

Lastly, plug your module into [fedimintd](https://github.com/fedimint/fedimint/blob/c0651f88068b5818cb42a1d038d3b55d26b41e56/fedimintd/src/bin/main.rs#L130-L132)
and [distributed config generation](https://github.com/fedimint/fedimint/blob/c0651f88068b5818cb42a1d038d3b55d26b41e56/fedimintd/src/bin/distributedgen.rs#L141-L148).

In order to interact with your module you may want to add some functionality to the [Client](https://github.com/fedimint/fedimint/blob/c0651f88068b5818cb42a1d038d3b55d26b41e56/client/client-lib/src/lib.rs#L199) and the [CLI](https://github.com/fedimint/fedimint/tree/c0651f88068b5818cb42a1d038d3b55d26b41e56/client/cli) which is built on top of the `Client`. It can also help to write an [integration test](https://github.com/fedimint/fedimint/blob/master/integrationtests/tests/tests.rs).
