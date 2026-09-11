/// Environment variable that specifies the directory of the gateway's database.
pub const FM_GATEWAY_DATA_DIR_ENV: &str = "FM_GATEWAY_DATA_DIR";

/// Environment variable that specifies the address the gateway's HTTP server
/// should listen on.
pub const FM_GATEWAY_LISTEN_ADDR_ENV: &str = "FM_GATEWAY_LISTEN_ADDR";

/// Environment variable that specifies the URL that clients can use to make
/// requests to the gateway.
pub const FM_GATEWAY_API_ADDR_ENV: &str = "FM_GATEWAY_API_ADDR";

/// Environment variable that specifies the bcrypt password hash.
pub const FM_GATEWAY_BCRYPT_PASSWORD_HASH_ENV: &str = "FM_GATEWAY_BCRYPT_PASSWORD_HASH";

/// Environment variable that specifies the bcrypt password hash for the gateway
/// liquidity manager.
pub const FM_GATEWAY_LIQUIDITY_MANAGER_BCRYPT_PASSWORD_HASH_ENV: &str =
    "FM_GATEWAY_LIQUIDITY_MANAGER_BCRYPT_PASSWORD_HASH";

/// Environment variable that specifies that Bitcoin network that the gateway
/// should use. Must match the network of the Lightning node.
pub const FM_GATEWAY_NETWORK_ENV: &str = "FM_GATEWAY_NETWORK";

/// Environment variable that instructs the gateway how many route hints to
/// include in LNv1 invoices.
pub const FM_NUMBER_OF_ROUTE_HINTS_ENV: &str = "FM_NUMBER_OF_ROUTE_HINTS";

/// Environment variable that specifies the mnemonic that the gateway should use
/// for ecash and the LDK Node should use for onchain funds. If not set, a
/// mnemonic will be generated. This environment variable can be used for
/// recovering from an existing mnemonic.
pub const FM_GATEWAY_MNEMONIC_ENV: &str = "FM_GATEWAY_MNEMONIC";

/// Environment variable that instructs the gateway to run in "debug mode",
/// which allows errors to return to clients without redacting private
/// information.
pub const FM_DEBUG_GATEWAY_ENV: &str = "FM_DEBUG_GATEWAY";

/// Environment variable that instructs the gateway to skip waiting for the
/// bitcoin node to sync to the chain.
pub const FM_GATEWAY_SKIP_WAIT_FOR_SYNC_ENV: &str = "FM_GATEWAY_SKIP_WAIT_FOR_SYNC";

/// Environment variable to select database backend (rocksdb or cursed-redb)
pub const FM_DB_BACKEND_ENV: &str = "FM_DB_BACKEND";

/// The username to use when connecting to a bitcoin node over RPC
pub const FM_BITCOIND_USERNAME_ENV: &str = "FM_BITCOIND_USERNAME";

/// The password to use when connecting to a bitcoin node over RPC
pub const FM_BITCOIND_PASSWORD_ENV: &str = "FM_BITCOIND_PASSWORD";

/// The URL to use when connecting to a bitcoin node over RPC.
/// Should not include authentication parameters: (e.g `http://127.0.0.1:8332`)
pub const FM_BITCOIND_URL_ENV: &str = "FM_BITCOIND_URL";

/// The URL to use when connecting to an Esplora server for bitcoin blockchain
/// data
pub const FM_ESPLORA_URL_ENV: &str = "FM_ESPLORA_URL";

/// Environment variable for customizing the default routing fees
pub const FM_DEFAULT_ROUTING_FEES_ENV: &str = "FM_DEFAULT_ROUTING_FEES";

/// Environment variable for customizing the default transaction fees
pub const FM_DEFAULT_TRANSACTION_FEES_ENV: &str = "FM_DEFAULT_TRANSACTION_FEES";

/// Environment variable that specifies the address the gateway's Iroh endpoint
/// should listen on.
pub const FM_GATEWAY_IROH_LISTEN_ADDR_ENV: &str = "FM_GATEWAY_IROH_LISTEN_ADDR";

/// Environment variable that specifies the address the gateway's metrics server
/// should listen on. If not set, metrics server will bind to localhost on the
/// UI port + 1.
pub const FM_GATEWAY_METRICS_LISTEN_ADDR_ENV: &str = "FM_GATEWAY_METRICS_LISTEN_ADDR";

/// Environment variable that instructs the gateway to generate a mnemonic if
/// one has not already been set.
pub const FM_GATEWAY_SKIP_SETUP_ENV: &str = "FM_GATEWAY_SKIP_SETUP";

/// Environment variable that specifies the maximum burst of requests to the
/// public invoice creation endpoint accepted before rate limiting kicks in.
pub const FM_GATEWAY_INVOICE_RATE_LIMIT_BURST_ENV: &str = "FM_GATEWAY_INVOICE_RATE_LIMIT_BURST";

/// Environment variable that specifies the sustained number of requests per
/// second to the public invoice creation endpoint accepted before rate
/// limiting kicks in.
pub const FM_GATEWAY_INVOICE_RATE_LIMIT_PER_SECOND_ENV: &str =
    "FM_GATEWAY_INVOICE_RATE_LIMIT_PER_SECOND";

/// Drawdown from the peak cumulative forwarding margin, as a percent of the
/// assets held at that peak, at which the gateway logs a warning. Default 2.
pub const FM_GATEWAY_DRAWDOWN_WARN_PCT_ENV: &str = "FM_GATEWAY_DRAWDOWN_WARN_PCT";

/// Drawdown percent at which the gateway refuses to start (and exits if
/// already running). Must exceed the warn threshold. Default 10. Raising it
/// is the documented recovery procedure after reviewing the breakdown.
pub const FM_GATEWAY_DRAWDOWN_HALT_PCT_ENV: &str = "FM_GATEWAY_DRAWDOWN_HALT_PCT";

/// Maximum ecash plus open positions the gateway will hold in any single
/// federation, in msat. Unset means unlimited.
pub const FM_GATEWAY_MAX_FEDERATION_EXPOSURE_MSAT_ENV: &str =
    "FM_GATEWAY_MAX_FEDERATION_EXPOSURE_MSAT";
