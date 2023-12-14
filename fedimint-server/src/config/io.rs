use std::collections::HashSet;
use std::fmt::Display;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use fedimint_aead::{encrypted_read, encrypted_write, get_encryption_key, LessSafeKey};
use fedimint_core::config::ServerModuleInitRegistry;
use lazy_static::lazy_static;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::config::ServerConfig;

/// Client configuration file
pub const CLIENT_CONFIG_FILE: &str = "client";

/// Server encrypted private keys file
pub const PRIVATE_KEYS_FILE: &str = "keys";

/// Server locally configurable file
pub const LOCAL_CONFIG_FILE: &str = "local";

/// Server consensus-only configurable file
pub const CONSENSUS_CONFIG_FILE: &str = "consensus";

/// Client connection string file
pub const CLIENT_INVITE_CODE_FILE: &str = "invite-code";

/// Salt backup for combining with the private key
pub const SALT_FILE: &str = "salt";

/// Plain-text stored password, used to restart the server without having to
/// send a password in via the API
pub const PASSWORD_FILE: &str = "password";

/// Database file name
pub const DB_FILE: &str = "database";

pub const PRIVATE_EXT: &str = "private";
pub const JSON_EXT: &str = "json";
const ENCRYPTED_EXT: &str = "encrypt";

lazy_static! {
    // Known server files persisted to disk
    pub static ref SERVER_FILES: HashSet<(String, String)> = {
        let mut m = HashSet::new();
        m.insert((CLIENT_CONFIG_FILE.to_owned(), JSON_EXT.to_owned()));
        m.insert((PRIVATE_KEYS_FILE.to_owned(), ENCRYPTED_EXT.to_owned()));
        m.insert((LOCAL_CONFIG_FILE.to_owned(), JSON_EXT.to_owned()));
        m.insert((CONSENSUS_CONFIG_FILE.to_owned(), JSON_EXT.to_owned()));
        m.insert((CLIENT_INVITE_CODE_FILE.to_owned(), "".to_owned()));
        m.insert((SALT_FILE.to_owned(), PRIVATE_EXT.to_owned()));
        m.insert((PASSWORD_FILE.to_owned(), PRIVATE_EXT.to_owned()));
        m
    };
}

/// Temporary directiry where server configs are stored / removed through the
/// setup process On setup complete, the configs are moved to the server config
/// directory and the staging directory is removed
pub const CONFIG_STAGING_DIR: &str = "cfg_staging";

/// Reads the server from the local, private, and consensus cfg files
pub fn read_server_config(password: &str, path: PathBuf) -> anyhow::Result<ServerConfig> {
    let salt = read_salt_file(path.clone())?;
    let key = get_encryption_key(password, &salt)?;

    Ok(ServerConfig {
        consensus: plaintext_json_read(path.join(CONSENSUS_CONFIG_FILE))?,
        local: plaintext_json_read(path.join(LOCAL_CONFIG_FILE))?,
        private: encrypted_json_read(&key, path.join(PRIVATE_KEYS_FILE))?,
    })
}

fn read_salt_file(path: PathBuf) -> anyhow::Result<String> {
    let salt = fs::read_to_string(path.join(SALT_FILE).with_extension(PRIVATE_EXT))?;
    Ok(salt)
}

pub fn read_plain_password(path: PathBuf) -> anyhow::Result<String> {
    let password = fs::read_to_string(path.join(PASSWORD_FILE).with_extension(PRIVATE_EXT))?;
    Ok(password)
}

/// Reads a plaintext json file into a struct
fn plaintext_json_read<T: Serialize + DeserializeOwned>(path: PathBuf) -> anyhow::Result<T> {
    let string = fs::read_to_string(path.with_extension(JSON_EXT))?;
    Ok(serde_json::from_str(&string)?)
}

/// Reads an encrypted json file into a struct
fn encrypted_json_read<T: Serialize + DeserializeOwned>(
    key: &LessSafeKey,
    path: PathBuf,
) -> anyhow::Result<T> {
    let decrypted = encrypted_read(key, path.with_extension(ENCRYPTED_EXT));
    let string = String::from_utf8(decrypted?)?;
    Ok(serde_json::from_str(&string)?)
}

/// Writes the server into configuration files (private keys encrypted)
pub fn write_server_config(
    server: &ServerConfig,
    path: PathBuf,
    password: &str,
    module_config_gens: &ServerModuleInitRegistry,
) -> anyhow::Result<()> {
    let salt = read_salt_file(path.clone())?;
    let key = get_encryption_key(password, &salt)?;

    let client_config = server.consensus.to_client_config(module_config_gens)?;
    plaintext_json_write(&server.local, path.join(LOCAL_CONFIG_FILE))?;
    plaintext_json_write(&server.consensus, path.join(CONSENSUS_CONFIG_FILE))?;
    plaintext_display_write(
        &server.get_invite_code(),
        &path.join(CLIENT_INVITE_CODE_FILE),
    )?;
    plaintext_json_write(&client_config, path.join(CLIENT_CONFIG_FILE))?;
    encrypted_json_write(&server.private, &key, path.join(PRIVATE_KEYS_FILE))
}

/// Writes struct into a plaintext json file
fn plaintext_json_write<T: Serialize + DeserializeOwned>(
    obj: &T,
    path: PathBuf,
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
    path: PathBuf,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_string(obj)?.into_bytes();
    encrypted_write(bytes, key, path.with_extension(ENCRYPTED_EXT))
}
