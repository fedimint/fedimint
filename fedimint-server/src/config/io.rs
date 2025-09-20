use std::fmt::Display;
use std::fs;
use std::io::Write;
use std::path::Path;

use fedimint_aead::{LessSafeKey, encrypted_read, encrypted_write, get_encryption_key};
use fedimint_core::invite_code::InviteCode;
use fedimint_server_core::ServerModuleInitRegistry;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::config::ServerConfig;

/// Client configuration file
pub const CLIENT_CONFIG: &str = "client";

/// Server encrypted private keys file
pub const PRIVATE_CONFIG: &str = "private";

/// Server locally configurable file
pub const LOCAL_CONFIG: &str = "local";

/// Server consensus-only configurable file
pub const CONSENSUS_CONFIG: &str = "consensus";

/// Client connection string file
pub const CLIENT_INVITE_CODE_FILE: &str = "invite-code";

/// Salt backup for combining with the private key
pub const SALT_FILE: &str = "private.salt";

/// Plain-text stored password, used to restart the server without having to
/// send a password in via the API
pub const PLAINTEXT_PASSWORD: &str = "password.private";

/// Database file name
pub const DB_FILE: &str = "database";

pub const JSON_EXT: &str = "json";

pub const ENCRYPTED_EXT: &str = "encrypt";

/// Reads the server from the local, private, and consensus cfg files
pub fn read_server_config(password: &str, path: &Path) -> anyhow::Result<ServerConfig> {
    let salt = fs::read_to_string(path.join(SALT_FILE))?;
    let key = get_encryption_key(password, &salt)?;

    Ok(ServerConfig {
        consensus: plaintext_json_read(&path.join(CONSENSUS_CONFIG))?,
        local: plaintext_json_read(&path.join(LOCAL_CONFIG))?,
        private: encrypted_json_read(&key, &path.join(PRIVATE_CONFIG))?,
    })
}

/// Reads a plaintext json file into a struct
fn plaintext_json_read<T: Serialize + DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let string = fs::read_to_string(path.with_extension(JSON_EXT))?;
    Ok(serde_json::from_str(&string)?)
}

/// Reads an encrypted json file into a struct
fn encrypted_json_read<T: Serialize + DeserializeOwned>(
    key: &LessSafeKey,
    path: &Path,
) -> anyhow::Result<T> {
    let decrypted = encrypted_read(key, path.with_extension(ENCRYPTED_EXT));
    let string = String::from_utf8(decrypted?)?;
    Ok(serde_json::from_str(&string)?)
}

/// Writes the server into configuration files (private keys encrypted)
pub fn write_server_config(
    server: &ServerConfig,
    path: &Path,
    password: &str,
    module_config_gens: &ServerModuleInitRegistry,
    api_secret: Option<String>,
) -> anyhow::Result<()> {
    let salt = fs::read_to_string(path.join(SALT_FILE))?;
    let key = get_encryption_key(password, &salt)?;

    let client_config = server.consensus.to_client_config(module_config_gens)?;
    plaintext_json_write(&server.local, &path.join(LOCAL_CONFIG))?;
    plaintext_json_write(&server.consensus, &path.join(CONSENSUS_CONFIG))?;
    plaintext_display_write(
        &InviteCode::new(
            server.consensus.api_endpoints[&server.local.identity]
                .url
                .clone(),
            server.local.identity,
            server.calculate_federation_id(),
            api_secret,
        ),
        &path.join(CLIENT_INVITE_CODE_FILE),
    )?;
    plaintext_json_write(&client_config, &path.join(CLIENT_CONFIG))?;
    encrypted_json_write(&server.private, &key, &path.join(PRIVATE_CONFIG))
}

/// Writes struct into a plaintext json file
fn plaintext_json_write<T: Serialize + DeserializeOwned>(
    obj: &T,
    path: &Path,
) -> anyhow::Result<()> {
    let file = fs::File::options()
        .create_new(true)
        .write(true)
        .open(path.with_extension(JSON_EXT))?;

    serde_json::to_writer_pretty(file, obj)?;
    Ok(())
}

fn plaintext_display_write<T: Display>(obj: &T, path: &Path) -> anyhow::Result<()> {
    let mut file = fs::File::options()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(obj.to_string().as_bytes())?;
    Ok(())
}

/// Writes struct into an encrypted json file
fn encrypted_json_write<T: Serialize + DeserializeOwned>(
    obj: &T,
    key: &LessSafeKey,
    path: &Path,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_string(obj)?.into_bytes();
    encrypted_write(bytes, key, path.with_extension(ENCRYPTED_EXT))
}
