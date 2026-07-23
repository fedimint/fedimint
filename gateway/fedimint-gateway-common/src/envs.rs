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

/// Environment variable for overriding the iroh secret key
pub const FM_GATEWAY_IROH_SECRET_KEY_OVERRIDE_ENV: &str = "FM_GATEWAY_IROH_SECRET_KEY_OVERRIDE";

/// Environment variable that specifies the `time_pref` used in LND
/// `SendPaymentRequest`. Must parse as an f64 in the range [-1.0, 1.0], where
/// -1 optimizes for fees and 1 optimizes for reliability.
pub const FM_LND_TIME_PREF_ENV: &str = "FM_LND_TIME_PREF";

/// Environment variable that specifies how long (in seconds) LND will keep
/// trying to route an outgoing payment before giving up. Passed as
/// `timeout_seconds` in LND `SendPaymentRequest`. Must parse as an i32 in the
/// range [1, 600].
pub const FM_LND_PAYMENT_TIMEOUT_SECS_ENV: &str = "FM_LND_PAYMENT_TIMEOUT_SECS";
