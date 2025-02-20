/// Environment variable that specifies the URL to connect to LND. Necessary for
/// LND configuration.
pub const FM_LND_RPC_ADDR_ENV: &str = "FM_LND_RPC_ADDR";

/// Environment variable that specifies the location of LND's TLS certificate.
/// Necessary for LND configuration.
pub const FM_LND_TLS_CERT_ENV: &str = "FM_LND_TLS_CERT";

/// Environment variable that specifies the location of LND's macaroon.
/// Necessary for LND configuration.
pub const FM_LND_MACAROON_ENV: &str = "FM_LND_MACAROON";

/// Environment variable that specifies the URL of an Esplora server.
/// Necessary for LDK configuration if using esplora as the backend.
pub const FM_LDK_ESPLORA_SERVER_URL: &str = "FM_LDK_ESPLORA_SERVER_URL";

/// Environment variable that specifies the bitcoind node.
/// Necessary for LDK configuration if using bitcoind as the backend.
pub const FM_LDK_BITCOIND_RPC_URL: &str = "FM_LDK_BITCOIND_RPC_URL";

/// Environment variable that specifies the Bitcoin network that the LDK Node
/// should use. Must match `FM_GATEWAY_NETWORK`. Necessary for LDK
/// configuration.
pub const FM_LDK_NETWORK: &str = "FM_LDK_NETWORK";

/// Environment variable the specifies the port that the LDK Node should use.
/// Necessary for LDK configuration.
pub const FM_PORT_LDK: &str = "FM_PORT_LDK";
