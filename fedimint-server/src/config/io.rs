use std::fmt::Display;
use std::fs;
use std::path::Path;

use fedimint_aead::{LessSafeKey, encrypted_read, get_encryption_key};
use fedimint_logging::LOG_CORE;
use fedimint_server_core::ServerModuleInitRegistry;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::warn;

use crate::config::ServerConfig;

/// Client configuration file
pub const CLIENT_CONFIG: &str = "client";

/// Server private keys file
pub const PRIVATE_CONFIG: &str = "private";

/// Server locally configurable file
pub const LOCAL_CONFIG: &str = "local";

/// Server consensus-only configurable file
pub const CONSENSUS_CONFIG: &str = "consensus";

/// Client connection string file
pub const CLIENT_INVITE_CODE_FILE: &str = "invite-code";

/// Legacy salt file for combining with the private key
const SALT_FILE: &str = "private.salt";

/// Legacy plain-text stored password
pub const PLAINTEXT_PASSWORD: &str = "password.private";

/// Legacy encrypted file extension
const ENCRYPTED_EXT: &str = "encrypt";

/// Database file name
pub const DB_FILE: &str = "database";

pub const JSON_EXT: &str = "json";

/// Reads the server config from plaintext JSON files. Falls back to reading
/// the legacy encrypted format using the password.private file if the
/// plaintext private config does not exist.
pub fn read_server_config(path: &Path) -> anyhow::Result<ServerConfig> {
    if path.join(PRIVATE_CONFIG).with_extension(JSON_EXT).exists() {
        return read_server_config_plaintext(path);
    }

    read_server_config_legacy_encrypted(path)
}

/// Reads the server config from plaintext JSON files
fn read_server_config_plaintext(path: &Path) -> anyhow::Result<ServerConfig> {
    Ok(ServerConfig {
        consensus: plaintext_json_read(&path.join(CONSENSUS_CONFIG))?,
        local: plaintext_json_read(&path.join(LOCAL_CONFIG))?,
        private: plaintext_json_read(&path.join(PRIVATE_CONFIG))?,
    })
}

/// Reads the server config with the legacy encrypted private config format,
/// using the password from the password.private file.
fn read_server_config_legacy_encrypted(path: &Path) -> anyhow::Result<ServerConfig> {
    let password_untrimmed = fs::read_to_string(path.join(PLAINTEXT_PASSWORD))?;
    let password = trim_password(&password_untrimmed);
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

/// Writes the server into configuration files as plaintext JSON.
pub fn write_server_config(
    server: &ServerConfig,
    path: &Path,
    module_config_gens: &ServerModuleInitRegistry,
    api_secret: Option<String>,
) -> anyhow::Result<()> {
    let client_config = server.consensus.to_client_config(module_config_gens)?;
    plaintext_json_write(&server.local, &path.join(LOCAL_CONFIG))?;
    plaintext_json_write(&server.consensus, &path.join(CONSENSUS_CONFIG))?;
    plaintext_display_write(
        &server.get_invite_code(api_secret),
        &path.join(CLIENT_INVITE_CODE_FILE),
    )?;
    plaintext_json_write(&client_config, &path.join(CLIENT_CONFIG))?;
    plaintext_json_write(&server.private, &path.join(PRIVATE_CONFIG))
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
    use std::io::Write;
    let mut file = fs::File::options()
        .create_new(true)
        .write(true)
        .open(path)?;
    file.write_all(obj.to_string().as_bytes())?;
    Ok(())
}

/// We definitely don't want leading/trailing newlines in passwords, and a user
/// editing the file manually will probably get a free newline added
/// by the text editor.
fn trim_password(password: &str) -> &str {
    let password_fully_trimmed = password.trim();
    if password_fully_trimmed != password {
        warn!(
            target: LOG_CORE,
            "Password in the password file contains leading/trailing whitespaces. This will an error in the future."
        );
    }
    password_fully_trimmed
}
