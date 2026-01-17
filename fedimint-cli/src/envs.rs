// Env variable to set the working directory of the client containing the config
// and db
pub const FM_CLIENT_DIR_ENV: &str = "FM_CLIENT_DIR";

// Env variable to set the peer id of the guardian
pub const FM_OUR_ID_ENV: &str = "FM_OUR_ID";

// Env variable to set the guardian password for authentication
pub const FM_PASSWORD_ENV: &str = "FM_PASSWORD";

// Env variable to use Tor connector, instead of default Tcp/ClearNet.
pub const FM_USE_TOR_ENV: &str = "FM_USE_TOR";

pub const FM_IROH_ENABLE_DHT_ENV: &str = "FM_IROH_ENABLE_DHT";

pub const FM_IROH_ENABLE_NEXT_ENV: &str = "FM_IROH_ENABLE_NEXT";

// Api authentication secret
pub const FM_API_SECRET_ENV: &str = "FM_API_SECRET";

// Env variable to select database backend (rocksdb or redb)
pub const FM_DB_BACKEND_ENV: &str = "FM_DB_BACKEND";

/// Salt backup for combining with the private key
pub const SALT_FILE: &str = "private.salt";
