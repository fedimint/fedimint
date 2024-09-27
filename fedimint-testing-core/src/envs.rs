// Env variable to TODO
pub const FM_PREPARE_DB_MIGRATION_SNAPSHOTS_ENV: &str = "FM_PREPARE_DB_MIGRATION_SNAPSHOTS";

// Env variable to TODO
pub const FM_TEST_USE_REAL_DAEMONS_ENV: &str = "FM_TEST_USE_REAL_DAEMONS";

// Env variable to TODO
pub const FM_PORT_ESPLORA_ENV: &str = "FM_PORT_ESPLORA";

// Env variable to TODO
pub const FM_TEST_DIR_ENV: &str = "FM_TEST_DIR";

// Env variable to TODO
pub const FM_TEST_BITCOIND_RPC_ENV: &str = "FM_TEST_BITCOIND_RPC";

// Overrides the wallet server's Bitcoin RPC kind used in testing fixtures.
// This is necessary instead of `FM_FORCE_BITCOIN_RPC_KIND_ENV` since that
// overrides both the wallet client and server's Bitcoin RPC.
pub const FM_TEST_BACKEND_BITCOIN_RPC_KIND_ENV: &str = "FM_TEST_BACKEND_BITCOIN_RPC_KIND";

// Overrides the wallet server's Bitcoin RPC URL used in testing fixtures.
// This is necessary instead of `FM_FORCE_BITCOIN_RPC_URL_ENV` since that
// overrides both the wallet client and server's Bitcoin RPC.
pub const FM_TEST_BACKEND_BITCOIN_RPC_URL_ENV: &str = "FM_TEST_BACKEND_BITCOIN_RPC_URL";
