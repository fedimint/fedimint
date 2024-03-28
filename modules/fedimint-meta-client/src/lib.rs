pub mod api;
#[cfg(feature = "cli")]
pub mod cli;
pub mod db;
pub mod states;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::time::Duration;

use anyhow::{bail, Context as AnyhowContext};
use api::MetaFederationApi;
use common::{MetaConsensusValue, MetaKey, MetaValue};
use db::DbKeyPrefix;
use fedimint_client::db::ClientMigrationFn;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientModule, IClientModule};
use fedimint_client::sm::Context;
use fedimint_core::api::DynModuleApi;
use fedimint_core::config::{parse_meta_value_static, META_OVERRIDE_URL_KEY};
use fedimint_core::core::Decoder;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::module::{
    ApiAuth, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::task::sleep;
use fedimint_core::util::retry;
use fedimint_core::{apply, async_trait_maybe_send, push_db_pair_items, Amount, PeerId};
pub use fedimint_meta_common as common;
use fedimint_meta_common::{MetaCommonInit, MetaModuleTypes};
use futures::future::OptionFuture;
use futures::StreamExt;
use serde::de::DeserializeOwned;
use states::MetaStateMachine;
use strum::IntoEnumIterator;
use tokio::join;
use tracing::{debug, warn};

use crate::db::{LegacyMetaOverrideCacheKey, MetaCacheKey};

// Q: do we define this elsewhere already? Afaik only one of these slots is
// meant to be used for now
const PRIMARY_META_KEY: MetaKey = MetaKey(0);

#[derive(Debug)]
pub struct MetaClientModule {
    module_api: DynModuleApi,
    admin_auth: Option<ApiAuth>,
    legacy_config_meta: MetaFields,
    db: Database,
}

impl MetaClientModule {
    fn admin_auth(&self) -> anyhow::Result<ApiAuth> {
        self.admin_auth
            .clone()
            .ok_or_else(|| anyhow::format_err!("Admin auth not set"))
    }

    /// Submit a meta consensus value
    ///
    /// When *threshold* amount of peers submits the exact same value it
    /// becomes a new consensus value.
    ///
    /// To "cancel" previous vote, peer can submit a value equal to the current
    /// consensus value.
    pub async fn submit(&self, key: MetaKey, value: MetaValue) -> anyhow::Result<()> {
        self.module_api
            .submit(key, value, self.admin_auth()?)
            .await?;

        Ok(())
    }

    /// Get the current meta consensus value along with it's revision
    ///
    /// See [`Self::get_consensus_value_rev`] to use when checking for updates.
    pub async fn get_consensus_value(
        &self,
        key: MetaKey,
    ) -> anyhow::Result<Option<MetaConsensusValue>> {
        Ok(self.module_api.get_consensus(key).await?)
    }

    /// Get the current meta consensus value revision
    ///
    /// Each time a meta consensus value changes, the revision increases,
    /// so checking just the revision can save a lot of bandwidth in periodic
    /// checks.
    pub async fn get_consensus_value_rev(&self, key: MetaKey) -> anyhow::Result<Option<u64>> {
        Ok(self.module_api.get_consensus_rev(key).await?)
    }

    /// Get current submissions to change the meta consensus value.
    ///
    /// Upon changing the consensus
    pub async fn get_submissions(
        &self,
        key: MetaKey,
    ) -> anyhow::Result<BTreeMap<PeerId, MetaValue>> {
        Ok(self
            .module_api
            .get_submissions(key, self.admin_auth()?)
            .await?)
    }

    /// Returns the value of a given meta field, using all three kinds of
    /// sources for backwards compatibility:
    ///   1. Consensus meta from this module
    ///   3. Legacy override meta, if so defined in the client config (the
    ///      consensus meta will be ignored for this since we are retiring the
    ///      override meta)
    ///   2. Legacy meta fields from the global client config
    ///
    /// The value comes from a cache that is kept up to date asynchronously.
    pub async fn get_meta_field_any_source<T: DeserializeOwned + 'static>(
        &self,
        field_name: &str,
    ) -> Option<T> {
        // Try to find the value in this module's consensus meta
        if let Some(value) = self
            .db
            .begin_transaction_nc()
            .await
            .get_value(&MetaCacheKey)
            .await
            .and_then(|consensus_meta| consensus_meta.get(field_name).cloned())
            .and_then(|value_str| {
                // Note how we use plain JSON parsing for new meta fields while old ones are
                // still parsed with the lenient parser that allows strings to not be JSON
                // encoded, but rather to be raw strings. For legacy meta this is necessary, but
                // going forward we should insist on valid JSON.
                serde_json::from_str(&value_str)
                    .map_err(|e| warn!("Could not parse consensus meta field: {e:?}"))
                    .ok()
            })
        {
            return Some(value);
        }

        // Try to find the field in override meta
        if let Some(value) = self
            .db
            .begin_transaction_nc()
            .await
            .get_value(&LegacyMetaOverrideCacheKey)
            .await
            .and_then(|consensus_meta| consensus_meta.get(field_name).cloned())
            .and_then(|value_str| {
                // Lenient parsing for legacy fields
                parse_meta_value_static(&value_str)
                    .map_err(|e| warn!("Could not parse override meta field: {e:?}"))
                    .ok()
            })
        {
            return Some(value);
        }

        // Lastly, fall back to static meta fields in the client config
        self.legacy_config_meta
            .get(field_name)
            .and_then(|value_str| {
                // Lenient parsing for legacy fields
                parse_meta_value_static(value_str)
                    .map_err(|e| warn!("Could not parse override meta field: {e:?}"))
                    .ok()
            })
    }
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct MetaClientContext {
    pub meta_decoder: Decoder,
}

// TODO: Boiler-plate
impl Context for MetaClientContext {}

#[apply(async_trait_maybe_send!)]
impl ClientModule for MetaClientModule {
    type Init = MetaClientInit;
    type Common = MetaModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = MetaClientContext;
    type States = MetaStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        MetaClientContext {
            meta_decoder: self.decoder(),
        }
    }

    fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<TransactionItemAmount> {
        unreachable!()
    }

    fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<TransactionItemAmount> {
        unreachable!()
    }

    fn supports_being_primary(&self) -> bool {
        false
    }

    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>) -> Amount {
        Amount::ZERO
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> anyhow::Result<serde_json::Value> {
        cli::handle_cli_command(self, args).await
    }
}

#[derive(Debug, Clone)]
pub struct MetaClientInit;

// TODO: Boilerplate-code
#[apply(async_trait_maybe_send!)]
impl ModuleInit for MetaClientInit {
    type Common = MetaCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        #[allow(clippy::never_loop)]
        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::LegacyMetaOverrideCache => {
                    push_db_pair_items!(
                        dbtx,
                        LegacyMetaOverrideCacheKey,
                        LegacyMetaOverrideCacheKey,
                        MetaFields,
                        items,
                        "LegacyMetaFields"
                    );
                }
                DbKeyPrefix::MetaCache => {
                    push_db_pair_items!(
                        dbtx,
                        MetaCacheKey,
                        MetaCacheKey,
                        MetaFields,
                        items,
                        "MetaFields"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for MetaClientInit {
    type Module = MetaClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        args.task_group().spawn_cancellable(
            "meta cache updater",
            run_meta_cache_updater(
                args.legacy_meta_fields().clone(),
                args.module_api().clone(),
                args.db().clone(),
            ),
        );

        Ok(MetaClientModule {
            module_api: args.module_api().clone(),
            admin_auth: args.admin_auth().cloned(),
            legacy_config_meta: args.legacy_meta_fields().clone(),
            db: args.db().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientMigrationFn> {
        BTreeMap::new()
    }
}

type MetaFields = BTreeMap<String, String>;

/// If fetching metadata fails, how long should we wait before retrying
const META_FETCH_RETRY_INTERVAL: Duration = Duration::from_secs(1);
/// How long do we consider fetched metadata valid
const META_FETCH_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 5);

async fn run_meta_cache_updater(config_meta: MetaFields, module_api: DynModuleApi, db: Database) {
    let meta_override_url: Option<String> = config_meta
        .get(META_OVERRIDE_URL_KEY)
        .and_then(|value| parse_meta_value_static(value).ok().flatten());
    let update_legacy_override_meta: OptionFuture<_> = meta_override_url
        .as_ref()
        .map(|meta_override_url| {
            run_legacy_override_meta_cache_updater(meta_override_url, db.clone())
        })
        .into();
    let update_module_meta = run_meta_module_cache_updater(module_api, db);

    join!(update_legacy_override_meta, update_module_meta);
}

async fn run_legacy_override_meta_cache_updater(meta_override_url: &str, db: Database) {
    let http_client = reqwest::Client::new();
    let fetch_override_meta = || async {
        let response = http_client
            .get(meta_override_url)
            .send()
            .await
            .context("Meta override source could not be fetched")?;

        debug!("Meta override source returned status: {response:?}");

        if response.status() != reqwest::StatusCode::OK {
            bail!(
                "Meta override request returned non-OK status code: {}",
                response.status()
            );
        }

        let meta_fields_raw = response
            .json::<BTreeMap<String, serde_json::Value>>()
            .await
            .context("Meta override could not be parsed as JSON")?;

        let meta_fields = meta_fields_raw
            .into_iter()
            .filter_map(|(key, value)| match value.as_str() {
                Some(value_str) => Some((key, value_str.to_owned())),
                None => {
                    warn!("Meta override map contained non-string key: {key}");
                    None
                }
            })
            .collect::<BTreeMap<_, _>>();

        Ok(meta_fields)
    };

    loop {
        let meta_fields = retry(
            "Fetch override meta",
            fetch_override_meta,
            META_FETCH_RETRY_INTERVAL,
            u32::MAX,
        )
        .await
        .expect("Will crash after 136 years if error persists");
        db.autocommit(
            move |dbtx, _| {
                let meta_fields_inner = meta_fields.clone();
                Box::pin(async move {
                    dbtx.insert_entry(&LegacyMetaOverrideCacheKey, &meta_fields_inner)
                        .await;
                    Result::<(), Infallible>::Ok(())
                })
            },
            None,
        )
        .await
        .expect("Will never fail");

        sleep(META_FETCH_REFRESH_INTERVAL).await;
    }
}

async fn run_meta_module_cache_updater(module_api: DynModuleApi, db: Database) {
    let fetch_meta = || async {
        module_api
            .get_consensus(PRIMARY_META_KEY)
            .await?
            .map(|value| {
                value
                    .value
                    .json::<BTreeMap<String, String>>()
                    .context("Failed to parse consensus meta fields")
            })
            .transpose()
            .map(Option::unwrap_or_default)
    };
    loop {
        let meta_fields = retry(
            "Fetch meta",
            fetch_meta,
            META_FETCH_RETRY_INTERVAL,
            u32::MAX,
        )
        .await
        .expect("Will crash after 136 years if error persists");
        db.autocommit(
            move |dbtx, _| {
                let meta_fields_inner = meta_fields.clone();
                Box::pin(async move {
                    dbtx.insert_entry(&MetaCacheKey, &meta_fields_inner).await;
                    Result::<(), Infallible>::Ok(())
                })
            },
            None,
        )
        .await
        .expect("Will never fail");

        sleep(META_FETCH_REFRESH_INTERVAL).await;
    }
}
