# Debugging Helpers

- [RUST_LOG syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives)
- To log all database requests for a specific key: `RUST_LOG="fedimint_api[{key=ContractKey.*}]=debug"`. 
You can use any other regex inplace of `ContractKey.*`, it matches with debug format of key.

- To log all api requests that server `RUST_LOG="fedimint_server::request"`

- [Inspect and manipulate the database using `dbtool`](../fedimint-dbtool/README.md) (low level, see `fedimint-dbdump` for a higher-level inspection tool)
