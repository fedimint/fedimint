use anyhow::Result;
use bitcoin_hashes::hex::ToHex;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use fedimint_api::db::Database;
use fedimint_api::module::registry::ModuleDecoderRegistry;

#[derive(Debug, Clone, Parser)]
struct Options {
    database: String,
    #[command(subcommand)]
    command: DbCommand,
}

/// Tool to inspect and manipulate rocksdb databases. All binary arguments (keys, values) have to be
/// hex encoded.
#[derive(Debug, Clone, Subcommand)]
enum DbCommand {
    /// List all key-value pairs where the key begins with `prefix`
    List {
        #[arg(value_parser = hex_parser)]
        prefix: Bytes,
    },
    /// Write a key-value pair to the database, overwriting the previous value if present
    Write {
        #[arg(value_parser = hex_parser)]
        key: Bytes,
        #[arg(value_parser = hex_parser)]
        value: Bytes,
    },
    /// Delete a single entry from the database identified by `key`
    Delete {
        #[arg(value_parser = hex_parser)]
        key: Bytes,
    },
}

fn hex_parser(hex: &str) -> Result<Bytes> {
    let bytes: Vec<u8> = bitcoin_hashes::hex::FromHex::from_hex(hex)?;
    Ok(bytes.into())
}

async fn open_db(path: &str) -> Result<Database> {
    let rocksdb = fedimint_rocksdb::RocksDb::open(path)?;
    Ok(Database::new(rocksdb, ModuleDecoderRegistry::default()))
}

fn print_kv(key: &[u8], value: &[u8]) {
    println!("{} {}", key.to_hex(), value.to_hex());
}

#[tokio::main]
async fn main() {
    let options: Options = Options::parse();

    let db = open_db(&options.database).await.expect("Failed to open DB");
    let mut dbtx = db.begin_transaction().await;

    match options.command {
        DbCommand::List { prefix } => {
            let prefix_iter = dbtx.raw_find_by_prefix(&prefix).await;
            for db_res in prefix_iter {
                let (key, value) = db_res.expect("DB error");
                print_kv(&key, &value);
            }
        }
        DbCommand::Write { key, value } => {
            dbtx.raw_insert_bytes(&key, value.into())
                .await
                .expect("DB error");
        }
        DbCommand::Delete { key } => {
            dbtx.raw_remove_entry(&key).await.expect("DB error");
        }
    }

    dbtx.commit_tx().await.expect("DB error");
}
