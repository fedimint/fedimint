// faucet.rs

// Env variable to TODO
pub const FM_FAUCET_BIND_ADDR_ENV: &str = "FM_FAUCET_BIND_ADDR";

// Env variable to TODO
pub const FM_BITCOIN_RPC_URL_ENV: &str = "FM_BITCOIN_RPC_URL";

// Env variable to TODO
pub const FM_CLN_SOCKET_ENV: &str = "FM_CLN_SOCKET";

// Env variable to TODO
pub const FM_PORT_GW_LND_ENV: &str = "FM_PORT_GW_LND";

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

// devfed.rs

// Env variable to define the gateway_id of the CLN client
pub const FM_GWID_CLN_ENV: &str = "FM_GWID_CLN";

// Env variable to define the gateway_id of the LND client
pub const FM_GWID_LND_ENV: &str = "FM_GWID_LND";

// cli.rs

// Env variable to set the testing directory of the client
pub const FM_TEST_DIR_ENV: &str = "FM_TEST_DIR";

// Env variable to set the size of the federation
pub const FM_FED_SIZE_ENV: &str = "FM_FED_SIZE";

// Env variable to create a link to the test dir under this path
pub const FM_LINK_TEST_DIR_ENV: &str = "FM_LINK_TEST_DIR";

// Env variable to run a degraded federation with FM_OFFLINE_NODES shutdown
pub const FM_OFFLINE_NODES_ENV: &str = "FM_OFFLINE_NODES";

// Env variable to set a federation's invite code
pub const FM_INVITE_CODE_ENV: &str = "FM_INVITE_CODE";

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

// Env variable to override lightning-cli binary set:
pub const FM_LIGHTNING_CLI_BASE_EXECUTABLE_ENV: &str = "FM_LIGHTNING_CLI_BASE_EXECUTABLE";

// Env variable to override lightning-cli default command set:
pub const FM_LIGHTNING_CLI_ENV: &str = "FM_LIGHTNING_CLI";

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

// Env variable to override lightningd binary set:
pub const FM_LIGHTNINGD_BASE_EXECUTABLE_ENV: &str = "FM_LIGHTNINGD_BASE_EXECUTABLE";

// Env variable to override lnd binary set:
pub const FM_LND_BASE_EXECUTABLE_ENV: &str = "FM_LND_BASE_EXECUTABLE";

// Env variable to override electrs binary set:
pub const FM_ELECTRS_BASE_EXECUTABLE_ENV: &str = "FM_ELECTRS_BASE_EXECUTABLE";

// Env variable to override esplora binary set:
pub const FM_ESPLORA_BASE_EXECUTABLE_ENV: &str = "FM_ESPLORA_BASE_EXECUTABLE";

// Env variable to override esplora binary set:
pub const FM_RECOVERYTOOL_BASE_EXECUTABLE_ENV: &str = "FM_RECOVERYTOOL_BASE_EXECUTABLE";

// Env variable to override esplora binary set:
pub const FM_FAUCET_BASE_EXECUTABLE_ENV: &str = "FM_FAUCET_BASE_EXECUTABLE";

// Env variable to override esplora binary set:
pub const FM_FEDIMINT_DBTOOL_BASE_EXECUTABLE_ENV: &str = "FM_FEDIMINT_DBTOOL_BASE_EXECUTABLE";

// Env variable to set the logs directory
pub const FM_LOGS_DIR_ENV: &str = "FM_LOGS_DIR";

// Env variable to TODO
pub const FM_BACKWARDS_COMPATIBILITY_TEST_ENV: &str = "FM_BACKWARDS_COMPATIBILITY_TEST";

// Env variable to define command for the CLN client
pub const FM_GWCLI_CLN_ENV: &str = "FM_GWCLI_CLN";

// Env variable to define command for the LND client
pub const FM_GWCLI_LND_ENV: &str = "FM_GWCLI_LND";

/// Make `devimint` print stderr of called commands directly on its own stderr
pub const FM_DEVIMINT_CMD_INHERIT_STDERR_ENV: &str = "FM_DEVIMINT_CMD_INHERIT_STDERR";
