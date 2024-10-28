/// Environment variable that specifies the directory of the gateway's database.
pub const FM_GATEWAY_DATA_DIR_ENV: &str = "FM_GATEWAY_DATA_DIR";

/// Environment variable that specifies the address the gateway's HTTP server
/// should listen on.
pub const FM_GATEWAY_LISTEN_ADDR_ENV: &str = "FM_GATEWAY_LISTEN_ADDR";

/// Environment variable that specifies the URL that clients can use to make
/// requests to the gateway.
pub const FM_GATEWAY_API_ADDR_ENV: &str = "FM_GATEWAY_API_ADDR";

/// Environment variable that specifies the password. This is only applied if
/// there is no password set, otherwise it is ignored.
pub const FM_GATEWAY_PASSWORD_ENV: &str = "FM_GATEWAY_PASSWORD";

/// Environment variable that specifies that Bitcoin network that the gateway
/// should use. Must match the network of the Lightning node.
pub const FM_GATEWAY_NETWORK_ENV: &str = "FM_GATEWAY_NETWORK";

/// Environment variable that specifies the default routing fees the gateway
/// takes for outgoing and incoming payments. Only applied to newly joined
/// federations.
pub const FM_DEFAULT_GATEWAY_FEES_ENV: &str = "FM_DEFAULT_GATEWAY_FEES";

/// Environment variable that instructs the gateway how many route hints to
/// include in LNv1 invoices.
pub const FM_NUMBER_OF_ROUTE_HINTS_ENV: &str = "FM_NUMBER_OF_ROUTE_HINTS";

/// Environment variable that specifies the URL to connect to LND. Necessary for
/// LND configuration.
pub const FM_LND_RPC_ADDR_ENV: &str = "FM_LND_RPC_ADDR";

/// Environment variable that specifies the location of LND's TLS certificate.
/// Necessary for LND configuration.
pub const FM_LND_TLS_CERT_ENV: &str = "FM_LND_TLS_CERT";

/// Environment variable that specifies the location of LND's macaroon.
/// Necessary for LND configuration.
pub const FM_LND_MACAROON_ENV: &str = "FM_LND_MACAROON";

/// Environment variable that specifies the URL of an Esplora server. Necessary
/// for LDK configuration.
pub const FM_LDK_ESPLORA_SERVER_URL: &str = "FM_LDK_ESPLORA_SERVER_URL";

/// Environment variable that specifies the Bitcoin network that the LDK Node
/// should use. Must match `FM_GATEWAY_NETWORK`. Necessary for LDK
/// configuration.
pub const FM_LDK_NETWORK: &str = "FM_LDK_NETWORK";

/// Environment variable the specifies the port that the LDK Node should use.
/// Necessary for LDK configuration.
pub const FM_PORT_LDK: &str = "FM_PORT_LDK";

/// Environment variable that specifies the address that the Core Lightning
/// extension should listen on. Will be removed in v0.6
pub const FM_CLN_EXTENSION_LISTEN_ADDRESS_ENV: &str = "FM_CLN_EXTENSION_LISTEN_ADDRESS";

/// Environment variable that specifies the URL that the gateway can use to
/// connect to the Core Lightning extension. Will be removed in v0.6.
pub const FM_GATEWAY_LIGHTNING_ADDR_ENV: &str = "FM_GATEWAY_LIGHTNING_ADDR";

/// Environment variable that specifies the mnemonic that the gateway should use
/// for ecash and the LDK Node should use for onchain funds. If not set, a
/// mnemonic will be generated. This environment variable can be used for
/// recovering from an existing mnemonic.
pub const FM_GATEWAY_MNEMONIC_ENV: &str = "FM_GATEWAY_MNEMONIC";

/// Environment variable that specifies the "module mode" the gateway should run
/// in. Options are "LNv1", "LNv2", or "All". It is not recommended to run "All"
/// in production so that clients are not able to use the same gateway to create
/// LNv1 and LNv2 invoices.
pub const FM_GATEWAY_LIGHTNING_MODULE_MODE_ENV: &str = "FM_GATEWAY_LIGHTNING_MODULE_MODE";

/// Environment variable that instructs the gateway to run in "debug mode",
/// which allows errors to return to clients without redacting private
/// information.
pub const FM_DEBUG_GATEWAY_ENV: &str = "FM_DEBUG_GATEWAY";

pub const FM_GATEWAY_SKIP_WAIT_FOR_SYNC_ENV: &str = "FM_GATEWAY_SKIP_WAIT_FOR_SYNC";
