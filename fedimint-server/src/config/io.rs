use std::fmt::Display;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::ensure;
use fedimint_aead::{LessSafeKey, encrypted_read, encrypted_write, get_encryption_key};
use fedimint_core::util::write_new;
use fedimint_logging::LOG_CORE;
use fedimint_server_core::ServerModuleInitRegistry;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::{debug, info, warn};

use crate::config::{ServerConfig, ServerConfigPrivate};

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

/// Database file name (legacy RocksDB directory)
pub const DB_FILE: &str = "database";

/// Database file name (redb file)
pub const REDB_FILE: &str = "fedimintd.redb";

pub const JSON_EXT: &str = "json";

pub const ENCRYPTED_EXT: &str = "encrypt";

pub const NEW_VERSION_FILE_EXT: &str = "new";

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
        &server.get_invite_code(api_secret),
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
pub fn encrypted_json_write<T: Serialize + DeserializeOwned>(
    obj: &T,
    key: &LessSafeKey,
    path: &Path,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_string(obj)?.into_bytes();
    encrypted_write(bytes, key, path.with_extension(ENCRYPTED_EXT))
}

/// We definitely don't want leading/trailing newlines in passwords, and a user
/// editing the file manually will probably get a free newline added
/// by the text editor.
pub fn trim_password(password: &str) -> &str {
    let password_fully_trimmed = password.trim();
    if password_fully_trimmed != password {
        warn!(
            target: LOG_CORE,
            "Password in the password file contains leading/trailing whitespaces. This will an error in the future."
        );
    }
    password_fully_trimmed
}

pub fn backup_copy_path(original: &Path) -> PathBuf {
    original.with_extension("bak")
}

pub fn create_backup_copy(original: &Path) -> anyhow::Result<()> {
    let backup_path = backup_copy_path(original);
    info!(target: LOG_CORE, ?original, ?backup_path, "Creating backup copy of file");
    ensure!(
        !backup_path.exists(),
        "Already have a backup at {backup_path:?}, would be overwritten"
    );
    fs::copy(original, backup_path)?;
    Ok(())
}

/// Re-encrypts the private config with a new password.
///
/// Note that we assume that the in-memory secret config equals the on-disk
/// secret config. If the process is interrupted,
/// [`recover_interrupted_password_change`] will fix it on startup.
///
/// As an additional safetynet this function creates backup copies of all files
/// being overwritten. These will be deleted by [`finalize_password_change`]
/// after the config has been read successfully for the first time after a
/// password change.
pub fn reencrypt_private_config(
    data_dir: &Path,
    private_config: &ServerConfigPrivate,
    new_password: &str,
) -> anyhow::Result<()> {
    info!(target: LOG_CORE, ?data_dir, "Re-encrypting private config with new password");
    let trimmed_password = trim_password(new_password);

    // we keep the same salt so we don't have to atomically update 3 files, 2 is
    // annoying enough (if we have to write the password file)
    let salt = fs::read_to_string(data_dir.join(SALT_FILE))?;
    let new_key = get_encryption_key(trimmed_password, &salt)?;

    let password_file_path = data_dir.join(PLAINTEXT_PASSWORD);
    let private_config_path = data_dir.join(PRIVATE_CONFIG).with_extension(ENCRYPTED_EXT);

    // Make backup copies of all files to be overwritten
    debug!(target: LOG_CORE, "Creating backup of private config");
    let password_file_present = password_file_path.exists();
    if password_file_present {
        create_backup_copy(&password_file_path)?;
    }
    create_backup_copy(&private_config_path)?;

    // Ensure backups are written durably before setting up password change
    OpenOptions::new().read(true).open(data_dir)?.sync_all()?;

    // Create new private config with updated password
    let new_private_config = {
        let mut new_private_config = private_config.clone();
        trimmed_password.clone_into(&mut new_private_config.api_auth.0);
        new_private_config
    };

    // Write new files to temporary locations so they can be moved into place
    // atomically later. This avoids data corruption if the process is killed while
    // writing the files.
    //
    // Note that we write the password file first and later delete the private
    // config file last. This way we can use the existence of the private config
    // file to detect an interrupted password change and ensure it's driven to
    // completion. We can't do the same with the password file since it might not be
    // present at all. This also means that, if we see a stray temp password file,
    // we can just delete it since the newly encrypted private config was never
    // written, so the old password is still valid.
    debug!(target: LOG_CORE, "Creating temporary files");
    let temp_password_file_path = password_file_path.with_extension(NEW_VERSION_FILE_EXT);
    if password_file_present {
        write_new(&temp_password_file_path, trimmed_password)?;
    }

    let temp_private_config_path = private_config_path.with_extension(NEW_VERSION_FILE_EXT);
    // We use the encrypted_write fn directly since the JSON version of it would
    // overwrite the file extension.
    let private_config_bytes = serde_json::to_string(&new_private_config)?.into_bytes();
    encrypted_write(
        private_config_bytes,
        &new_key,
        temp_private_config_path.clone(),
    )?;

    // Ensure temp files are written durably before starting to overwrite files
    OpenOptions::new().read(true).open(data_dir)?.sync_all()?;

    debug!(target: LOG_CORE, "Moving temp files to final location");
    // Move new files into place. This can't be done atomically, so there's recovery
    // logic in `recover_interrupted_password_change` on startup.
    // DO NOT CHANGE MOVE ORDER, SEE ABOVE
    fs::rename(&temp_private_config_path, &private_config_path)?;
    if password_file_present {
        fs::rename(&temp_password_file_path, &password_file_path)?;
    }

    Ok(())
}

/// If [`reencrypt_private_config`] was interrupted, this function ensures that
/// the system is in a consistent state, either pre-password change or
/// post-password change.
pub fn recover_interrupted_password_change(data_dir: &Path) -> anyhow::Result<()> {
    let password_file_path = data_dir.join(PLAINTEXT_PASSWORD);
    let private_config_path = data_dir.join(PRIVATE_CONFIG).with_extension(ENCRYPTED_EXT);

    let temp_password_file_path = password_file_path.with_extension(NEW_VERSION_FILE_EXT);
    let temp_private_config_path = private_config_path.with_extension(NEW_VERSION_FILE_EXT);

    match (
        temp_private_config_path.exists(),
        temp_password_file_path.exists(),
    ) {
        (false, false) => {
            // Default case, nothing to do, no interrupted password change
        }
        (true, password_file_exists) => {
            warn!(
                target: LOG_CORE,
                "Found temporary private config, password change process was interrupted. Recovering..."
            );

            // DO NOT CHANGE MOVE ORDER, SEE reencrypt_private_config
            if password_file_exists {
                fs::rename(&temp_password_file_path, &password_file_path)?;
            }
            fs::rename(&temp_private_config_path, &private_config_path)?;
        }
        (false, true) => {
            warn!(
                target: LOG_CORE,
                "Found only the temporary password file but no encrypted config. Cleaning up the temporary password file."
            );
            fs::remove_file(&temp_password_file_path)?;
        }
    }

    Ok(())
}

/// Clean up private config and password file backups after the config has been
/// read successfully for the first time after a password change.
pub fn finalize_password_change(data_dir: &Path) -> anyhow::Result<()> {
    let password_backup_path = backup_copy_path(&data_dir.join(PLAINTEXT_PASSWORD));
    if password_backup_path.exists() {
        fs::remove_file(&password_backup_path)?;
    }

    let private_config_backup_path =
        backup_copy_path(&data_dir.join(PRIVATE_CONFIG).with_extension(ENCRYPTED_EXT));
    if private_config_backup_path.exists() {
        fs::remove_file(&private_config_backup_path)?;
    }

    Ok(())
}
