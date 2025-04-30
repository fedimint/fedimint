#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::return_self_not_must_use)]

pub mod envs;

use std::collections::HashMap;
use std::iter::once;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use fedimint_client::module_init::{ClientModuleInitRegistry, IClientModuleInit};
use fedimint_client::sm::executor::{ActiveStateKeyPrefix, InactiveStateKeyPrefix};
use fedimint_client_module::module::init::ClientModuleInit;
use fedimint_client_module::transaction::{
    TRANSACTION_SUBMISSION_MODULE_INSTANCE, tx_submission_sm_decoder,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::{
    IDatabaseTransactionOpsCore, IDatabaseTransactionOpsCoreTyped, IRawDatabaseExt,
};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
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
use serde_json::json;

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

    /// Dump state machine states from a client DB
    DumpStates {
        #[clap(long, default_value = "0=ln,1=mint,2=wallet,3=meta", value_parser = parse_module_instance_ids)]
        modules: HashMap<ModuleInstanceId, ModuleKind>,
    },
}

fn parse_module_instance_ids(s: &str) -> Result<HashMap<ModuleInstanceId, ModuleKind>> {
    let mut map = HashMap::new();
    for module in s.split(',') {
        let (id, kind) = module.split_once('=').context("Syntax: id=kind")?;
        map.insert(id.parse()?, ModuleKind::clone_from_str(kind));
    }
    Ok(map)
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
            DbCommand::DumpStates { modules } => {
                self.run_dump_states(options, modules).await?;
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

    async fn run_dump_states(
        &self,
        options: &Options,
        modules: &HashMap<ModuleInstanceId, ModuleKind>,
    ) -> Result<()> {
        let module_decoders = modules
            .iter()
            .map(|(instance_id, module_kind)| {
                let (_, module_init) = self
                    .client_module_inits
                    .iter()
                    .find(|&(kind, _)| module_kind == kind)
                    .context(anyhow!("Unknown module kind: {module_kind}"))?;
                let dyn_client_init: &dyn IClientModuleInit = module_init.as_ref();
                let decoder = IClientModuleInit::decoder(dyn_client_init);
                Result::<_, anyhow::Error>::Ok((*instance_id, module_kind.clone(), decoder))
            })
            .chain(once(Ok((
                TRANSACTION_SUBMISSION_MODULE_INSTANCE,
                ModuleKind::from_static_str("tx_submission"),
                tx_submission_sm_decoder(),
            ))))
            .collect::<Result<Vec<_>, _>>()?;
        let decoder_registry = ModuleDecoderRegistry::new(module_decoders);

        let rocksdb = open_db(options).await.with_decoders(decoder_registry);
        let mut dbtx = rocksdb.begin_transaction_nc().await;

        let active_states = dbtx
            .find_by_prefix(&ActiveStateKeyPrefix)
            .await
            .map(|(active_state, state_meta)| {
                json!({
                    "operation_id": active_state.0.operation_id,
                    "state": format!("{:?}", active_state.0.state),
                    "state_raw": active_state.0.state.consensus_encode_to_hex(),
                    "meta": format!("{:?}", state_meta),
                })
            })
            .collect::<Vec<_>>()
            .await;

        let inactive_states = dbtx
            .find_by_prefix(&InactiveStateKeyPrefix)
            .await
            .map(|(inactive_state, state_meta)| {
                json!({
                    "operation_id": inactive_state.0.operation_id,
                    "state": format!("{:?}", inactive_state.0.state),
                    "state_raw": inactive_state.0.state.consensus_encode_to_hex(),
                    "meta": format!("{:?}", state_meta),
                })
            })
            .collect::<Vec<_>>()
            .await;

        let states = json!({
            "active_states": active_states,
            "inactive_states": inactive_states,
        });

        serde_json::to_writer(std::io::stdout(), &states).context("Failed to serialize states")?;

        Ok(())
    }
}

async fn open_db(options: &Options) -> fedimint_core::db::Database {
    fedimint_rocksdb::RocksDb::open(&options.database_dir)
        .await
        .unwrap()
        .into_database()
}
