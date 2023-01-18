use std::fs;
use std::path::PathBuf;

use anyhow::format_err;
use fedimint_server::config::{ModuleInitRegistry, ServerConfig};
use ring::aead::LessSafeKey;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::encrypt::{encrypted_read, encrypted_write};

pub mod distributedgen;
pub mod encrypt;
pub mod ui;

/// Version of the server code (should be the same among peers)
pub const CODE_VERSION: &str = env!("GIT_HASH");

/// Client configuration file
pub const CLIENT_CONFIG: &str = "client";

/// Server encrypted private keys file
pub const PRIVATE_CONFIG: &str = "private";

/// Server locally configurable file
pub const LOCAL_CONFIG: &str = "local";

/// Server consensus-only configurable file
pub const CONSENSUS_CONFIG: &str = "consensus";

/// Salt backup for combining with the private key
pub const SALT_FILE: &str = "private.salt";

/// Database file name
pub const DB_FILE: &str = "database";

/// Encrypted TLS private keys
pub const TLS_PK: &str = "tls-pk";

/// TLS public cert
pub const TLS_CERT: &str = "tls-cert";

pub const JSON_EXT: &str = "json";
const ENCRYPTED_EXT: &str = "encrypt";

/// Reads the server from the local, private, and consensus cfg files (private file encrypted)
pub fn read_server_configs(key: &LessSafeKey, path: PathBuf) -> anyhow::Result<ServerConfig> {
    Ok(ServerConfig {
        consensus: plaintext_json_read(path.join(CONSENSUS_CONFIG))?,
        local: plaintext_json_read(path.join(LOCAL_CONFIG))?,
        private: encrypted_json_read(key, path.join(PRIVATE_CONFIG))?,
    })
}

/// Reads a plaintext json file into a struct
pub fn plaintext_json_read<T: Serialize + DeserializeOwned>(path: PathBuf) -> anyhow::Result<T> {
    let string = fs::read_to_string(path.with_extension(JSON_EXT))?;
    Ok(serde_json::from_str(&string)?)
}

/// Reads an encrypted json file into a struct
pub fn encrypted_json_read<T: Serialize + DeserializeOwned>(
    key: &LessSafeKey,
    path: PathBuf,
) -> anyhow::Result<T> {
    let decrypted = encrypted_read(key, path.with_extension(ENCRYPTED_EXT));
    let string = String::from_utf8(decrypted?)?;
    Ok(serde_json::from_str(&string)?)
}

/// Writes the server into plaintext json configuration files (private keys not serialized)
pub fn write_nonprivate_configs(
    server: &ServerConfig,
    path: PathBuf,
    module_config_gens: &ModuleInitRegistry,
) -> anyhow::Result<()> {
    plaintext_json_write(&server.local, path.join(LOCAL_CONFIG))?;
    plaintext_json_write(&server.consensus, path.join(CONSENSUS_CONFIG))?;
    plaintext_json_write(
        &server
            .consensus
            .to_config_response(module_config_gens)
            .client,
        path.join(CLIENT_CONFIG),
    )
}

/// Writes struct into a plaintext json file
pub fn plaintext_json_write<T: Serialize + DeserializeOwned>(
    obj: &T,
    path: PathBuf,
) -> anyhow::Result<()> {
    let filename = path.with_extension(JSON_EXT);
    let file = fs::File::create(filename.clone())
        .map_err(|_| format_err!("Unable to create file {:?}", filename))?;
    serde_json::to_writer_pretty(file, obj)?;
    Ok(())
}

/// Writes struct into an encrypted json file
pub fn encrypted_json_write<T: Serialize + DeserializeOwned>(
    obj: &T,
    key: &LessSafeKey,
    path: PathBuf,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_string(obj)?.into_bytes();
    encrypted_write(bytes, key, path.with_extension(ENCRYPTED_EXT))
}
