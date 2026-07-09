/// Environment variable that specifies the URL to connect to LND. Necessary for
/// LND configuration.
pub const FM_LND_RPC_ADDR_ENV: &str = "FM_LND_RPC_ADDR";

/// Environment variable that specifies the location of LND's TLS certificate.
/// Necessary for LND configuration.
pub const FM_LND_TLS_CERT_ENV: &str = "FM_LND_TLS_CERT";

/// Environment variable that specifies the location of LND's macaroon.
/// Necessary for LND configuration.
pub const FM_LND_MACAROON_ENV: &str = "FM_LND_MACAROON";

/// Environment variable the specifies the port that the LDK Node should use.
/// Necessary for LDK configuration.
pub const FM_PORT_LDK: &str = "FM_PORT_LDK";

/// The alias for the LDK Node
pub const FM_LDK_ALIAS_ENV: &str = "FM_LDK_ALIAS";

/// Optional wallet birthday block height for the LDK Node to rescan from on
/// first startup (e.g. after restoring from seed). If unset, the wallet
/// checkpoints at the current chain tip and does not rescan history.
pub const FM_LDK_WALLET_RESCAN_FROM_HEIGHT_ENV: &str = "FM_LDK_WALLET_RESCAN_FROM_HEIGHT";

/// Environment variable for overriding the iroh secret key
pub const FM_GATEWAY_IROH_SECRET_KEY_OVERRIDE_ENV: &str = "FM_GATEWAY_IROH_SECRET_KEY_OVERRIDE";

/// Environment variable that specifies the `time_pref` used in LND
/// `SendPaymentRequest`. Must parse as an f64 in the range [-1.0, 1.0], where
/// -1 optimizes for fees and 1 optimizes for reliability.
pub const FM_LND_TIME_PREF_ENV: &str = "FM_LND_TIME_PREF";
