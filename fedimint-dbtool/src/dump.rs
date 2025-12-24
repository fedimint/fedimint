use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Context;
use erased_serde::Serialize;
use fedimint_client::db::{ClientConfigKey, OperationLogKeyPrefix};
use fedimint_client::module_init::ClientModuleInitRegistry;
use fedimint_client_module::oplog::OperationLogEntry;
use fedimint_core::config::{ClientConfig, CommonModuleInitRegistry};
use fedimint_core::core::ModuleKind;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersionKey, IDatabaseTransactionOpsCore,
    IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::push_db_pair_items;
use fedimint_gateway_server_db::GatewayDbtxNcExt as _;
use fedimint_rocksdb::RocksDbReadOnly;
use fedimint_server::config::ServerConfig;
use fedimint_server::config::io::read_server_config;
use fedimint_server::consensus::db as consensus_db;
use fedimint_server::core::{ServerModuleInitRegistry, ServerModuleInitRegistryExt};
use fedimint_server::db as server_db;
use fedimint_server::net::api::announcement::ApiAnnouncementPrefix;
use futures::StreamExt;
use strum::IntoEnumIterator;

macro_rules! push_db_pair_items_no_serde {
    ($dbtx:ident, $prefix_type:expr_2021, $key_type:ty, $value_type:ty, $map:ident, $key_literal:literal) => {
        let db_items = IDatabaseTransactionOpsCoreTyped::find_by_prefix($dbtx, &$prefix_type)
            .await
            .map(|(key, val)| {
                (
                    Encodable::consensus_encode_to_hex(&key),
                    SerdeWrapper::from_encodable(&val),
                )
            })
            .collect::<BTreeMap<_, _>>()
            .await;

        $map.insert($key_literal.to_string(), Box::new(db_items));
    };
}

#[derive(Debug, serde::Serialize)]
struct SerdeWrapper(#[serde(with = "hex::serde")] Vec<u8>);

impl SerdeWrapper {
    fn from_encodable<T: Encodable>(e: &T) -> SerdeWrapper {
        SerdeWrapper(e.consensus_encode_to_vec())
    }
}

/// Structure to hold the deserialized structs from the database.
/// Also includes metadata on which sections of the database to read.
pub struct DatabaseDump {
    serialized: BTreeMap<String, Box<dyn Serialize>>,
    read_only_db: Database,
    modules: Vec<String>,
    prefixes: Vec<String>,
    server_cfg: Option<ServerConfig>,
    module_inits: ServerModuleInitRegistry,
    client_cfg: Option<ClientConfig>,
    client_module_inits: ClientModuleInitRegistry,
}

impl DatabaseDump {
    pub async fn new(
        cfg_dir: PathBuf,
        data_dir: String,
        password: String,
        module_inits: ServerModuleInitRegistry,
        client_module_inits: ClientModuleInitRegistry,
        modules: Vec<String>,
        prefixes: Vec<String>,
    ) -> anyhow::Result<DatabaseDump> {
        let Ok(read_only_rocks_db) = RocksDbReadOnly::open_read_only(data_dir.clone()).await else {
            panic!("Error reading RocksDB database. Quitting...");
        };

        let read_only_db = Database::new(read_only_rocks_db, ModuleRegistry::default());

        let (server_cfg, client_cfg, decoders) = if let Ok(cfg) =
            read_server_config(&password, &cfg_dir).context("Failed to read server config")
        {
            // Successfully read the server's config, that means this database is a server
            // db
            let decoders = module_inits
                .available_decoders(cfg.iter_module_instances())
                .unwrap()
                .with_fallback();
            (Some(cfg), None, decoders)
        } else {
            // Check if this database is a client database by reading the `ClientConfig`
            // from the database.

            let mut dbtx = read_only_db.begin_transaction_nc().await;
            let client_cfg_or = dbtx.get_value(&ClientConfigKey).await;

            match client_cfg_or {
                Some(client_cfg) => {
                    // Successfully read the client config, that means this database is a client db
                    let kinds = client_cfg.modules.iter().map(|(k, v)| (*k, &v.kind));
                    let decoders = client_module_inits
                        .available_decoders(kinds)
                        .unwrap()
                        .with_fallback();
                    let client_cfg = client_cfg.redecode_raw(&decoders)?;
                    (None, Some(client_cfg), decoders)
                }
                _ => (None, None, ModuleDecoderRegistry::default()),
            }
        };

        Ok(DatabaseDump {
            serialized: BTreeMap::new(),
            read_only_db: read_only_db.with_decoders(decoders),
            modules,
            prefixes,
            server_cfg,
            module_inits,
            client_module_inits,
            client_cfg,
        })
    }
}

impl DatabaseDump {
    /// Prints the contents of the `BTreeMap` to a pretty JSON string
    fn print_database(&self) {
        let json = serde_json::to_string_pretty(&self.serialized).unwrap();
        println!("{json}");
    }

    async fn serialize_module(
        &mut self,
        module_id: &u16,
        kind: &ModuleKind,
        inits: CommonModuleInitRegistry,
    ) -> anyhow::Result<()> {
        if !self.modules.is_empty() && !self.modules.contains(&kind.to_string()) {
            return Ok(());
        }
        let mut dbtx = self.read_only_db.begin_transaction_nc().await;
        let db_version = dbtx.get_value(&DatabaseVersionKey(*module_id)).await;
        let mut isolated_dbtx = dbtx.to_ref_with_prefix_module_id(*module_id).0;

        match inits.get(kind) {
            None => {
                tracing::warn!(module_id, %kind, "Detected configuration for unsupported module");

                let mut module_serialized = BTreeMap::new();
                let filtered_prefixes = (0u8..=255).filter(|f| {
                    self.prefixes.is_empty()
                        || self.prefixes.contains(&f.to_string().to_lowercase())
                });

                let isolated_dbtx = &mut isolated_dbtx;

                for prefix in filtered_prefixes {
                    let db_items = isolated_dbtx
                        .raw_find_by_prefix(&[prefix])
                        .await?
                        .map(|(k, v)| {
                            (
                                k.consensus_encode_to_hex(),
                                Box::new(v.consensus_encode_to_hex()),
                            )
                        })
                        .collect::<BTreeMap<String, Box<_>>>()
                        .await;

                    module_serialized.extend(db_items);
                }
                self.serialized
                    .insert(format!("{kind}-{module_id}"), Box::new(module_serialized));
            }
            Some(init) => {
                let mut module_serialized = init
                    .dump_database(&mut isolated_dbtx.to_ref_nc(), self.prefixes.clone())
                    .await
                    .collect::<BTreeMap<String, _>>();

                if let Some(db_version) = db_version {
                    module_serialized.insert("Version".to_string(), Box::new(db_version));
                } else {
                    module_serialized
                        .insert("Version".to_string(), Box::new("Not Specified".to_string()));
                }

                self.serialized
                    .insert(format!("{kind}-{module_id}"), Box::new(module_serialized));
            }
        }

        Ok(())
    }

    async fn serialize_gateway(&mut self) -> anyhow::Result<()> {
        let mut dbtx = self.read_only_db.begin_transaction_nc().await;
        let gateway_serialized = dbtx.dump_database(self.prefixes.clone()).await;
        self.serialized
            .insert("gateway".to_string(), Box::new(gateway_serialized));
        Ok(())
    }

    /// Iterates through all the specified ranges in the database and retrieves
    /// the data for each range. Prints serialized contents at the end.
    pub async fn dump_database(&mut self) -> anyhow::Result<()> {
        if let Some(cfg) = self.server_cfg.clone() {
            if self.modules.is_empty() || self.modules.contains(&"consensus".to_string()) {
                self.retrieve_consensus_data().await;
            }

            for (module_id, module_cfg) in &cfg.consensus.modules {
                let kind = &module_cfg.kind;
                self.serialize_module(module_id, kind, self.module_inits.to_common())
                    .await?;
            }

            self.print_database();
            return Ok(());
        }

        if let Some(cfg) = self.client_cfg.clone() {
            self.serialized
                .insert("Client Config".into(), Box::new(cfg.to_json()));

            for (module_id, module_cfg) in &cfg.modules {
                let kind = &module_cfg.kind;
                let mut modules = Vec::new();
                if let Some(module) = self.client_module_inits.get(kind) {
                    modules.push(module.to_dyn_common());
                }

                let registry = CommonModuleInitRegistry::from(modules);
                self.serialize_module(module_id, kind, registry).await?;
            }

            {
                let mut dbtx = self.read_only_db.begin_transaction_nc().await;
                Self::write_serialized_client_operation_log(&mut self.serialized, &mut dbtx).await;
            }

            self.print_database();
            return Ok(());
        }

        self.serialize_gateway().await?;
        self.print_database();

        Ok(())
    }

    /// Iterates through each of the prefixes within the consensus range and
    /// retrieves the corresponding data.
    async fn retrieve_consensus_data(&mut self) {
        let filtered_prefixes = server_db::DbKeyPrefix::iter().filter(|prefix| {
            self.prefixes.is_empty() || self.prefixes.contains(&prefix.to_string().to_lowercase())
        });
        let mut dbtx = self.read_only_db.begin_transaction_nc().await;
        let mut consensus: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();

        for table in filtered_prefixes {
            Self::write_serialized_consensus_range(table, &mut dbtx, &mut consensus).await;
        }

        self.serialized
            .insert("Consensus".to_string(), Box::new(consensus));
    }

    async fn write_serialized_consensus_range(
        table: server_db::DbKeyPrefix,
        dbtx: &mut DatabaseTransaction<'_>,
        consensus: &mut BTreeMap<String, Box<dyn Serialize>>,
    ) {
        match table {
            server_db::DbKeyPrefix::AcceptedItem => {
                push_db_pair_items_no_serde!(
                    dbtx,
                    consensus_db::AcceptedItemPrefix,
                    server_db::AcceptedItemKey,
                    fedimint_server::consensus::AcceptedItem,
                    consensus,
                    "Accepted Items"
                );
            }
            server_db::DbKeyPrefix::AcceptedTransaction => {
                push_db_pair_items_no_serde!(
                    dbtx,
                    consensus_db::AcceptedTransactionKeyPrefix,
                    server_db::AcceptedTransactionKey,
                    fedimint_server::consensus::AcceptedTransaction,
                    consensus,
                    "Accepted Transactions"
                );
            }
            server_db::DbKeyPrefix::SignedSessionOutcome => {
                push_db_pair_items_no_serde!(
                    dbtx,
                    consensus_db::SignedSessionOutcomePrefix,
                    server_db::SignedBlockKey,
                    fedimint_server::consensus::SignedBlock,
                    consensus,
                    "Signed Blocks"
                );
            }
            server_db::DbKeyPrefix::AlephUnits => {
                push_db_pair_items_no_serde!(
                    dbtx,
                    consensus_db::AlephUnitsPrefix,
                    server_db::AlephUnitsKey,
                    Vec<u8>,
                    consensus,
                    "Aleph Units"
                );
            }
            // Module is a global prefix for all module data
            server_db::DbKeyPrefix::Module
            | server_db::DbKeyPrefix::ServerInfo
            | server_db::DbKeyPrefix::DatabaseVersion
            | server_db::DbKeyPrefix::ClientBackup => {}
            server_db::DbKeyPrefix::ApiAnnouncements => {
                push_db_pair_items_no_serde!(
                    dbtx,
                    ApiAnnouncementPrefix,
                    ApiAnnouncementKey,
                    fedimint_core::net::api_announcement::SignedApiAnnouncement,
                    consensus,
                    "API Announcements"
                );
            }
            server_db::DbKeyPrefix::GuardianMetadata => {
                push_db_pair_items_no_serde!(
                    dbtx,
                    fedimint_server::net::api::guardian_metadata::GuardianMetadataPrefix,
                    fedimint_server::net::api::guardian_metadata::GuardianMetadataKey,
                    fedimint_core::net::guardian_metadata::SignedGuardianMetadata,
                    consensus,
                    "Guardian Metadata"
                );
            }
        }
    }
    async fn write_serialized_client_operation_log(
        serialized: &mut BTreeMap<String, Box<dyn Serialize>>,
        dbtx: &mut DatabaseTransaction<'_>,
    ) {
        push_db_pair_items!(
            dbtx,
            OperationLogKeyPrefix,
            OperationLogKey,
            OperationLogEntry,
            serialized,
            "Operations"
        );
    }
}
