#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::return_self_not_must_use)]

pub mod envs;

use std::path::PathBuf;

use anyhow::Result;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client_module::module::init::ClientModuleInit;
use fedimint_core::db::{IDatabaseTransactionOpsCore, IRawDatabaseExt};
use fedimint_core::util::handle_version_hash_command;
use fedimint_ln_client::LightningClientInit;
use fedimint_ln_server::LightningInit;
use fedimint_logging::TracingSetup;
use fedimint_meta_client::MetaClientInit;
use fedimint_meta_server::MetaInit;
use fedimint_mint_client::MintClientInit;
use fedimint_mint_server::MintInit;
use fedimint_server::core::{ServerModuleInit, ServerModuleInitRegistry};
use fedimint_wallet_client::WalletClientInit;
use fedimint_wallet_server::WalletInit;
use futures::StreamExt;
use hex::ToHex;

use crate::dump::DatabaseDump;
use crate::envs::{FM_DBTOOL_CONFIG_DIR_ENV, FM_DBTOOL_DATABASE_ENV, FM_PASSWORD_ENV};

mod dump;

#[derive(Debug, Clone, Parser)]
#[command(version)]
struct Options {
    #[clap(long, env = FM_DBTOOL_DATABASE_ENV)]
    database_dir: String,

    #[clap(long, hide = true)]
    /// Run dbtool like it doesn't know about any module kind. This is a
    /// internal option for testing.
    no_modules: bool,

    #[command(subcommand)]
    command: DbCommand,
}

/// Tool to inspect and manipulate rocksdb databases. All binary arguments
/// (keys, values) have to be hex encoded.
#[derive(Debug, Clone, Subcommand)]
enum DbCommand {
    /// List all key-value pairs where the key begins with `prefix`
    List {
        #[arg(long, value_parser = hex_parser)]
        prefix: Bytes,
    },
    /// Write a key-value pair to the database, overwriting the previous value
    /// if present
    Write {
        #[arg(long, value_parser = hex_parser)]
        key: Bytes,
        #[arg(long, value_parser = hex_parser)]
        value: Bytes,
    },
    /// Delete a single entry from the database identified by `key`
    Delete {
        #[arg(long, value_parser = hex_parser)]
        key: Bytes,
    },
    /// Deletes all keys starting
    DeletePrefix {
        #[arg(long, value_parser = hex_parser)]
        prefix: Bytes,
    },
    /// Dump a subset of the specified database and serialize the retrieved data
    /// to JSON. Module and prefix are used to specify which subset of the
    /// database to dump. Password is used to decrypt the server's
    /// configuration file. If dumping the client database, the password can
    /// be an arbitrary string.
    Dump {
        #[clap(long, env = FM_DBTOOL_CONFIG_DIR_ENV)]
        cfg_dir: PathBuf,
        #[arg(long, env = FM_PASSWORD_ENV)]
        password: String,
        #[arg(long, required = false)]
        modules: Option<String>,
        #[arg(long, required = false)]
        prefixes: Option<String>,
    },
}

fn hex_parser(hex: &str) -> Result<Bytes> {
    let bytes: Vec<u8> = hex::FromHex::from_hex(hex)?;
    Ok(bytes.into())
}

fn print_kv(key: &[u8], value: &[u8]) {
    println!(
        "{} {}",
        key.encode_hex::<String>(),
        value.encode_hex::<String>()
    );
}

pub struct FedimintDBTool {
    server_module_inits: ServerModuleInitRegistry,
    client_module_inits: ClientModuleInitRegistry,
    cli_args: Options,
}

impl FedimintDBTool {
    /// Build a new `fedimintdb-tool` with a custom version hash
    pub fn new(version_hash: &str) -> anyhow::Result<Self> {
        handle_version_hash_command(version_hash);
        TracingSetup::default().init()?;

        Ok(Self {
            server_module_inits: ServerModuleInitRegistry::new(),
            client_module_inits: ClientModuleInitRegistry::new(),
            cli_args: Options::parse(),
        })
    }

    pub fn with_server_module_init<T>(mut self, r#gen: T) -> Self
    where
        T: ServerModuleInit + 'static + Send + Sync,
    {
        self.server_module_inits.attach(r#gen);
        self
    }

    pub fn with_client_module_init<T>(mut self, r#gen: T) -> Self
    where
        T: ClientModuleInit + 'static + Send + Sync,
    {
        self.client_module_inits.attach(r#gen);
        self
    }

    pub fn with_default_modules_inits(self) -> Self {
        self.with_server_module_init(WalletInit)
            .with_server_module_init(MintInit)
            .with_server_module_init(LightningInit)
            .with_server_module_init(fedimint_lnv2_server::LightningInit)
            .with_server_module_init(MetaInit)
            .with_client_module_init(WalletClientInit::default())
            .with_client_module_init(MintClientInit)
            .with_client_module_init(LightningClientInit::default())
            .with_client_module_init(fedimint_lnv2_client::LightningClientInit::default())
            .with_client_module_init(fedimint_walletv2_client::WalletClientInit)
            .with_client_module_init(MetaClientInit)
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let options = &self.cli_args;
        match &options.command {
            DbCommand::List { prefix } => {
                let rocksdb = open_db(options).await;
                let mut dbtx = rocksdb.begin_transaction().await;
                let prefix_iter = dbtx
                    .raw_find_by_prefix(prefix)
                    .await?
                    .collect::<Vec<_>>()
                    .await;
                for (key, value) in prefix_iter {
                    print_kv(&key, &value);
                }
                dbtx.commit_tx().await;
            }
            DbCommand::Write { key, value } => {
                let rocksdb = open_db(options).await;
                let mut dbtx = rocksdb.begin_transaction().await;
                dbtx.raw_insert_bytes(key, value)
                    .await
                    .expect("Error inserting entry into RocksDb");
                dbtx.commit_tx().await;
            }
            DbCommand::Delete { key } => {
                let rocksdb = open_db(options).await;
                let mut dbtx = rocksdb.begin_transaction().await;
                dbtx.raw_remove_entry(key)
                    .await
                    .expect("Error removing entry from RocksDb");
                dbtx.commit_tx().await;
            }
            DbCommand::Dump {
                cfg_dir,
                modules,
                prefixes,
                password,
            } => {
                let modules = match modules {
                    Some(mods) => mods
                        .split(',')
                        .map(|s| s.to_string().to_lowercase())
                        .collect::<Vec<String>>(),
                    None => Vec::new(),
                };

                let prefix_names = match prefixes {
                    Some(db_prefixes) => db_prefixes
                        .split(',')
                        .map(|s| s.to_string().to_lowercase())
                        .collect::<Vec<String>>(),
                    None => Vec::new(),
                };

                let (module_inits, client_module_inits) = if options.no_modules {
                    (
                        ServerModuleInitRegistry::new(),
                        ClientModuleInitRegistry::new(),
                    )
                } else {
                    (
                        self.server_module_inits.clone(),
                        self.client_module_inits.clone(),
                    )
                };

                let mut dbdump = DatabaseDump::new(
                    cfg_dir.clone(),
                    options.database_dir.clone(),
                    password.to_string(),
                    module_inits,
                    client_module_inits,
                    modules,
                    prefix_names,
                )
                .await?;
                dbdump.dump_database().await?;
            }
            DbCommand::DeletePrefix { prefix } => {
                let rocksdb = open_db(options).await;
                let mut dbtx = rocksdb.begin_transaction().await;
                dbtx.raw_remove_by_prefix(prefix).await?;
                dbtx.commit_tx().await;
            }
        }

        Ok(())
    }
}

async fn open_db(options: &Options) -> fedimint_core::db::Database {
    fedimint_rocksdb::RocksDb::build(&options.database_dir)
        .open()
        .await
        .unwrap()
        .into_database()
}
