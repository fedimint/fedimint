#![allow(where_clauses_object_safety)]

// https://github.com/dtolnay/async-trait/issues/228
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use bitcoin_hashes::hex::ToHex;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use fedimint_client::module::ClientModule;
use fedimint_client::sm::executor::{ActiveStateKeyPrefix, InactiveStateKeyPrefix};
use fedimint_client::sm::OperationId;
use fedimint_client::transaction::{
    tx_submission_sm_decoder, TRANSACTION_SUBMISSION_MODULE_INSTANCE,
};
use fedimint_client::DynGlobalClientContext;
use fedimint_client_legacy::modules::mint::MintClientModule;
use fedimint_client_legacy::modules::wallet::WalletClientModule;
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::core::{
    ModuleKind, LEGACY_HARDCODED_INSTANCE_ID_LN, LEGACY_HARDCODED_INSTANCE_ID_MINT,
    LEGACY_HARDCODED_INSTANCE_ID_WALLET,
};
use fedimint_core::db::notifications::Notifications;
use fedimint_core::db::{DatabaseTransaction, IDatabase, SingleUseDatabaseTransaction};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::DynServerModuleInit;
use fedimint_ln_server::LightningGen;
use fedimint_logging::TracingSetup;
use fedimint_mint_server::MintGen;
use fedimint_rocksdb::RocksDbReadOnly;
use fedimint_wallet_server::WalletGen;
use futures::StreamExt;
use itertools::Itertools;
use ln_gateway::ng::GatewayClientModule;

use crate::dump::DatabaseDump;

mod dump;

#[derive(Debug, Clone, Parser)]
struct Options {
    #[clap(long)]
    database: String,

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
    /// Dump a subset of the specified database and serialize the retrieved data
    /// to JSON. Module and prefix are used to specify which subset of the
    /// database to dump. Password is used to decrypt the server's
    /// configuration file. If dumping the client database, the password can
    /// be an arbitrary string.
    Dump {
        #[clap(long)]
        cfg_dir: PathBuf,
        #[arg(long, env = "FM_PASSWORD")]
        password: String,
        #[arg(long, required = false)]
        modules: Option<String>,
        #[arg(long, required = false)]
        prefixes: Option<String>,
    },

    /// Lists state machine states from a client database in the format:
    /// module instance | active | creation time | state debug print
    ListStates {
        /// List active states
        #[arg(long, required = false)]
        active: bool,
        /// List inactive states
        #[arg(long, required = false)]
        inactive: bool,
        /// Print the state debug output on multiple lines
        #[arg(long, required = false)]
        pretty: bool,
        /// Only show states belonging to operation
        #[arg(long, required = false)]
        operation: Option<String>,
        /// Only show states belonging to this module instance
        #[arg(long, required = false)]
        instance: Option<u16>,
    },
}

fn hex_parser(hex: &str) -> Result<Bytes> {
    let bytes: Vec<u8> = bitcoin_hashes::hex::FromHex::from_hex(hex)?;
    Ok(bytes.into())
}

fn print_kv(key: &[u8], value: &[u8]) {
    println!("{} {}", key.to_hex(), value.to_hex());
}

#[tokio::main]
async fn main() -> Result<()> {
    TracingSetup::default().init()?;
    let options: Options = Options::parse();

    match options.command {
        DbCommand::List { prefix } => {
            let rocksdb: Box<dyn IDatabase> =
                Box::new(fedimint_rocksdb::RocksDb::open(&options.database).unwrap());
            let mut dbtx = rocksdb.begin_transaction().await;
            let prefix_iter = dbtx
                .raw_find_by_prefix(&prefix)
                .await?
                .collect::<Vec<_>>()
                .await;
            for (key, value) in prefix_iter {
                print_kv(&key, &value);
            }
            dbtx.commit_tx().await.expect("Error committing to RocksDb");
        }
        DbCommand::Write { key, value } => {
            let rocksdb: Box<dyn IDatabase> =
                Box::new(fedimint_rocksdb::RocksDb::open(&options.database).unwrap());
            let mut dbtx = rocksdb.begin_transaction().await;
            dbtx.raw_insert_bytes(&key, &value)
                .await
                .expect("Error inserting entry into RocksDb");
            dbtx.commit_tx().await.expect("Error committing to RocksDb");
        }
        DbCommand::Delete { key } => {
            let rocksdb: Box<dyn IDatabase> =
                Box::new(fedimint_rocksdb::RocksDb::open(&options.database).unwrap());
            let mut dbtx = rocksdb.begin_transaction().await;
            dbtx.raw_remove_entry(&key)
                .await
                .expect("Error removing entry from RocksDb");
            dbtx.commit_tx().await.expect("Error committing to RocksDb");
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

            let module_inits = ServerModuleInitRegistry::from(if options.no_modules {
                vec![]
            } else {
                vec![
                    DynServerModuleInit::from(WalletGen),
                    DynServerModuleInit::from(MintGen),
                    DynServerModuleInit::from(LightningGen),
                ]
            });

            let mut dbdump = DatabaseDump::new(
                cfg_dir,
                options.database,
                password,
                module_inits,
                modules,
                prefix_names,
            );
            dbdump.dump_database().await?;
        }
        DbCommand::ListStates {
            active,
            inactive,
            pretty,
            operation,
            instance,
        } => {
            let decoders = module_decoders();

            let read_only_client = match RocksDbReadOnly::open_read_only(options.database) {
                Ok(db) => db,
                Err(_) => {
                    panic!("Error reading RocksDB database. Quitting...");
                }
            };

            let notifications = Box::new(Notifications::new());
            let single_use = SingleUseDatabaseTransaction::new(read_only_client);
            let mut dbtx = DatabaseTransaction::new(Box::new(single_use), decoders, &notifications);

            let active_states = if active {
                dbtx.find_by_prefix(&ActiveStateKeyPrefix::<DynGlobalClientContext>::new())
                    .await
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .map(|(key, value)| (value.created_at, key.state, true))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };

            let inactive_states = if inactive {
                dbtx.find_by_prefix(&InactiveStateKeyPrefix::<DynGlobalClientContext>::new())
                    .await
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .map(|(key, value)| (value.created_at, key.state, false))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };

            let filter_operation_id =
                operation.map(|operation_id_str| OperationId::from_str(&operation_id_str).unwrap());
            let states = inactive_states
                .into_iter()
                .chain(active_states)
                .filter(|(_, state, _)| {
                    let operation_ok = filter_operation_id
                        .map(|operation_id| state.operation_id() == operation_id)
                        .unwrap_or(true);

                    let instance_ok = instance
                        .map(|instance| state.module_instance_id() == instance)
                        .unwrap_or(true);

                    operation_ok && instance_ok
                })
                .sorted_by(|(time1, ..), (time2, ..)| time1.cmp(time2));

            for (time, state, active) in states {
                let datetime: DateTime<Utc> = time.into();
                let instance = state.module_instance_id();
                if pretty {
                    println!(
                        "{instance:5} {active:5} {} {:#?}",
                        datetime.format("%+"),
                        state
                    );
                } else {
                    println!(
                        "{instance:5} {active:5} {} {:?}",
                        datetime.format("%+"),
                        state
                    );
                }
            }
        }
    }

    Ok(())
}

fn module_decoders() -> ModuleDecoderRegistry {
    let mut decoders = ModuleDecoderRegistry::new(vec![
        (
            LEGACY_HARDCODED_INSTANCE_ID_WALLET,
            ModuleKind::from_static_str("wallet"),
            <WalletClientModule as ClientModule>::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_LN,
            ModuleKind::from_static_str("ln"),
            <GatewayClientModule as ClientModule>::decoder(),
        ),
        (
            LEGACY_HARDCODED_INSTANCE_ID_MINT,
            ModuleKind::from_static_str("mint"),
            <MintClientModule as ClientModule>::decoder(),
        ),
    ]);
    decoders.register_module(
        TRANSACTION_SUBMISSION_MODULE_INSTANCE,
        ModuleKind::from_static_str("tx_submission"),
        tx_submission_sm_decoder(),
    );
    decoders.with_fallback()
}
