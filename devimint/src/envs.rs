// tests.rs

// Env variable to TODO
pub const FM_PASSWORD_ENV: &str = "FM_PASSWORD";

// gatewayd.rs

// Env variable to TODO
pub const FM_GATEWAY_DATA_DIR_ENV: &str = "FM_GATEWAY_DATA_DIR";

// Env variable to TODO
pub const FM_GATEWAY_LISTEN_ADDR_ENV: &str = "FM_GATEWAY_LISTEN_ADDR";

// Env variable to TODO
pub const FM_GATEWAY_API_ADDR_ENV: &str = "FM_GATEWAY_API_ADDR";

// federation.rs

// Env variable to set client's data directory
pub const FM_DATA_DIR_ENV: &str = "FM_DATA_DIR";

// Env variable to set the working directory of the client containing the config
// and db
pub const FM_CLIENT_DIR_ENV: &str = "FM_CLIENT_DIR";

// cli.rs

// Env variable to set the testing directory of the client
pub const FM_TEST_DIR_ENV: &str = "FM_TEST_DIR";

// Env variable to set the size of the federation
pub const FM_FED_SIZE_ENV: &str = "FM_FED_SIZE";

// Env variable to set the number of federations to allocate for the test/run
pub const FM_NUM_FEDS_ENV: &str = "FM_NUM_FEDS";

// Env variable to create a link to the test dir under this path
pub const FM_LINK_TEST_DIR_ENV: &str = "FM_LINK_TEST_DIR";

// Env variable to run a degraded federation with FM_OFFLINE_NODES shutdown
pub const FM_OFFLINE_NODES_ENV: &str = "FM_OFFLINE_NODES";

// Fix base port for federation (fedimintds) port range
pub const FM_FEDERATIONS_BASE_PORT_ENV: &str = "FM_FEDERATIONS_BASE_PORT";

// Env variable to set a federation's invite code
pub const FM_INVITE_CODE_ENV: &str = "FM_INVITE_CODE";

// Env variable to stop in a pre-dkg stage of devimint
pub const FM_PRE_DKG_ENV: &str = "FM_PRE_DKG";

// util.rs

// Env variable to override gatewayd binary set:
pub const FM_GATEWAYD_BASE_EXECUTABLE_ENV: &str = "FM_GATEWAYD_BASE_EXECUTABLE";

// Env variable to override override fedimintd binary set:
pub const FM_FEDIMINTD_BASE_EXECUTABLE_ENV: &str = "FM_FEDIMINTD_BASE_EXECUTABLE";

// Env variable to override fedimint-cli binary set:
pub const FM_FEDIMINT_CLI_BASE_EXECUTABLE_ENV: &str = "FM_FEDIMINT_CLI_BASE_EXECUTABLE";

// Env variable to override fedimint-cli default command
// (like "$FM_FEDIMINT_CLI_BASE_EXECUTABLE --data-dir /tmp/xxx ....")
// set:
pub const FM_MINT_CLIENT_ENV: &str = "FM_MINT_CLIENT";

// Env variable to override gateway-cli binary set:
pub const FM_GATEWAY_CLI_BASE_EXECUTABLE_ENV: &str = "FM_GATEWAY_CLI_BASE_EXECUTABLE";

// Env variable to override fedimint-load-test-tool binary set:
pub const FM_LOAD_TEST_TOOL_BASE_EXECUTABLE_ENV: &str = "FM_LOAD_TEST_TOOL_BASE_EXECUTABLE";

// Env variable to override lncli binary set:
pub const FM_LNCLI_BASE_EXECUTABLE_ENV: &str = "FM_LNCLI_BASE_EXECUTABLE";

// Env variable to override lncli default command set:
pub const FM_LNCLI_ENV: &str = "FM_LNCLI";

// Env variable to override bitcoin-cli binary set:
pub const FM_BITCOIN_CLI_BASE_EXECUTABLE_ENV: &str = "FM_BITCOIN_CLI_BASE_EXECUTABLE";

// Env variable to override bitcoin-cli default command set:
pub const FM_BTC_CLIENT_ENV: &str = "FM_BTC_CLIENT";

// Env variable to override bitcoind binary set:
pub const FM_BITCOIND_BASE_EXECUTABLE_ENV: &str = "FM_BITCOIND_BASE_EXECUTABLE";

// Env variable to override lnd binary set:
pub const FM_LND_BASE_EXECUTABLE_ENV: &str = "FM_LND_BASE_EXECUTABLE";

// Env variable to override esplora binary set:
pub const FM_ESPLORA_BASE_EXECUTABLE_ENV: &str = "FM_ESPLORA_BASE_EXECUTABLE";

// Env variable to override esplora binary set:
pub const FM_RECOVERYTOOL_BASE_EXECUTABLE_ENV: &str = "FM_RECOVERYTOOL_BASE_EXECUTABLE";

// Env variable to override esplora binary set:
pub const FM_DEVIMINT_FAUCET_BASE_EXECUTABLE_ENV: &str = "FM_DEVIMINT_FAUCET_BASE_EXECUTABLE";

// Env variable to override esplora binary set:
pub const FM_FEDIMINT_DBTOOL_BASE_EXECUTABLE_ENV: &str = "FM_FEDIMINT_DBTOOL_BASE_EXECUTABLE";

// Env variable to set the logs directory
pub const FM_LOGS_DIR_ENV: &str = "FM_LOGS_DIR";

// Env variable to TODO
pub const FM_BACKWARDS_COMPATIBILITY_TEST_ENV: &str = "FM_BACKWARDS_COMPATIBILITY_TEST";

// Env variable to define command for the Gateway LND client
pub const FM_GWCLI_LND_ENV: &str = "FM_GWCLI_LND";

// Env variable to define command for the Gateway LDK client
pub const FM_GWCLI_LDK_ENV: &str = "FM_GWCLI_LDK";

/// Make `devimint` print stderr of called commands directly on its own stderr
pub const FM_DEVIMINT_CMD_INHERIT_STDERR_ENV: &str = "FM_DEVIMINT_CMD_INHERIT_STDERR";

/// Force devimint to run a test with a deprecated configuration
pub const FM_DEVIMINT_RUN_DEPRECATED_TESTS_ENV: &str = "FM_DEVIMINT_RUN_DEPRECATED_TESTS";

/// Devimint's "data dir" (think `/usr/devimint/`).
///
/// "Static" because we use "data dir" for the directory `devimint` puts all the
/// runtime state in, which is typically a per-invocation temporary directory.
///
/// Can be set during `cargo build` to force the default one, then available in
/// Rust code during building, and also checked at runtime to allow
/// overwriting.
pub const FM_DEVIMINT_STATIC_DATA_DIR_ENV: &str = "FM_DEVIMINT_STATIC_DATA_DIR";

/// Override LDK's Lightning port
pub const FM_PORT_LDK_ENV: &str = "FM_PORT_LDK";

// recurringd.rs

// Env variable for recurringd bind address
pub const FM_RECURRING_BIND_ADDRESS_ENV: &str = "FM_RECURRING_BIND_ADDRESS";

// Env variable for recurringd API address
pub const FM_RECURRING_API_ADDRESS_ENV: &str = "FM_RECURRING_API_ADDRESS";

// Env variable for recurringd data directory
pub const FM_RECURRING_DATA_DIR_ENV: &str = "FM_RECURRING_DATA_DIR";

// Env variable for recurringd API bearer token
pub const FM_RECURRING_API_BEARER_TOKEN_ENV: &str = "FM_RECURRING_API_BEARER_TOKEN";

// Env variable to override recurringd binary set:
pub const FM_RECURRINGD_BASE_EXECUTABLE_ENV: &str = "FM_RECURRINGD_BASE_EXECUTABLE";

// Env variable to override the iroh listen addr for the gateway
pub const FM_GATEWAY_IROH_LISTEN_ADDR_ENV: &str = "FM_GATEWAY_IROH_LISTEN_ADDR";

// Env variable to set the metrics listen addr for the gateway
pub const FM_GATEWAY_METRICS_LISTEN_ADDR_ENV: &str = "FM_GATEWAY_METRICS_LISTEN_ADDR";
