#![allow(where_clauses_object_safety)] // https://github.com/dtolnay/async-trait/issues/228
use std::path::PathBuf;

use anyhow::Result;
use bitcoin_hashes::hex::ToHex;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use fedimint_core::config::ServerModuleInitRegistry;
use fedimint_core::db::IDatabase;
use fedimint_core::module::DynServerModuleInit;
use fedimint_ln_server::LightningGen;
use fedimint_logging::TracingSetup;
use fedimint_mint_server::MintGen;
use fedimint_wallet_server::WalletGen;
use futures::StreamExt;

use crate::dump::DatabaseDump;

mod dump;

#[derive(Debug, Clone, Parser)]
struct Options {
    #[clap(long, env = "FM_DBTOOL_DATABASE")]
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
        #[clap(long, env = "FM_DBTOOL_CONFIG_DIR")]
        cfg_dir: PathBuf,
        #[arg(long, env = "FM_PASSWORD")]
        password: String,
        #[arg(long, required = false)]
        modules: Option<String>,
        #[arg(long, required = false)]
        prefixes: Option<String>,
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
            )?;
            dbdump.dump_database().await?;
        }
    }

    Ok(())
}
