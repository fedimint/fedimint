One way to think of Fedimint is as a framework for building federated applications with no single point of trust.

In order to build such an application, you need to fork the `fedimint` git repo. Create a new crate in the `modules` folder - you can use the [`fedimint-dummy-*`](https://github.com/fedimint/fedimint/tree/master/modules) crates as inspiration. Next `impl` two traits:

* [ServerModule](https://github.com/fedimint/fedimint/blob/3a808c44c94856c80d4b716ed853a882e83cb5c3/fedimint-core/src/module/mod.rs#L737-L892): defines how your module will interact with Fedimint consensus.
* [ServerModuleGen](https://github.com/fedimint/fedimint/blob/3a808c44c94856c80d4b716ed853a882e83cb5c3/fedimint-core/src/module/mod.rs#L517-L585): defines how configuration for your module will be generated.

Lastly, plug your module into [fedimintd](https://github.com/fedimint/fedimint/blob/master/fedimintd/src/bin/main.rs)
and [distributed config generation](https://github.com/fedimint/fedimint/blob/master/fedimintd/src/bin/distributedgen.rs).

In order to interact with your module you may want to add some functionality to the [Client](https://github.com/fedimint/fedimint/blob/3a808c44c94856c80d4b716ed853a882e83cb5c3/client/client-lib/src/lib.rs#L219) and the [CLI](https://github.com/fedimint/fedimint/tree/master/fedimint-cli) which is built on top of the `Client`. It can also help to write an [integration test](https://github.com/fedimint/fedimint/blob/master/integrationtests/tests/tests.rs).
