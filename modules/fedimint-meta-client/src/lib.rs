#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

pub mod api;
#[cfg(feature = "cli")]
pub mod cli;
pub mod db;
pub mod states;

use std::collections::BTreeMap;
use std::time::Duration;

use api::MetaFederationApi;
use common::{KIND, MetaConsensusValue, MetaKey, MetaValue};
use db::DbKeyPrefix;
use fedimint_api_client::api::{DynGlobalApi, DynModuleApi};
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::meta::{FetchKind, LegacyMetaSource, MetaSource, MetaValues};
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientModule, IClientModule};
use fedimint_client_module::sm::Context;
use fedimint_core::config::ClientConfig;
use fedimint_core::core::{Decoder, ModuleKind};
use fedimint_core::db::{DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::{
    Amounts, ApiAuth, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::util::backoff_util::FibonacciBackoff;
use fedimint_core::util::{backoff_util, retry};
use fedimint_core::{PeerId, apply, async_trait_maybe_send};
use fedimint_logging::LOG_CLIENT_MODULE_META;
pub use fedimint_meta_common as common;
use fedimint_meta_common::{DEFAULT_META_KEY, MetaCommonInit, MetaModuleTypes};
use states::MetaStateMachine;
use strum::IntoEnumIterator;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct MetaClientModule {
    module_api: DynModuleApi,
    admin_auth: Option<ApiAuth>,
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
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct MetaClientContext {
    pub meta_decoder: Decoder,
}

// TODO: Boiler-plate
impl Context for MetaClientContext {
    const KIND: Option<ModuleKind> = Some(KIND);
}

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

    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        unreachable!()
    }

    async fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        unreachable!()
    }

    fn output_fee(
        &self,
        _amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        unreachable!()
    }

    async fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        unreachable!()
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
impl ModuleInit for MetaClientInit {
    type Common = MetaCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        #[allow(clippy::never_loop)]
        for table in filtered_prefixes {
            match table {}
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
        Ok(MetaClientModule {
            module_api: args.module_api().clone(),
            admin_auth: args.admin_auth().cloned(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}

/// Meta source fetching meta values from the meta module if available or the
/// legacy meta source otherwise.
#[derive(Clone, Debug, Default)]
pub struct MetaModuleMetaSourceWithFallback<S = LegacyMetaSource> {
    legacy: S,
}

impl<S> MetaModuleMetaSourceWithFallback<S> {
    pub fn new(legacy: S) -> Self {
        Self { legacy }
    }
}

#[apply(async_trait_maybe_send!)]
impl<S: MetaSource> MetaSource for MetaModuleMetaSourceWithFallback<S> {
    async fn wait_for_update(&self) {
        fedimint_core::runtime::sleep(Duration::from_secs(10 * 60)).await;
    }

    async fn fetch(
        &self,
        client_config: &ClientConfig,
        api: &DynGlobalApi,
        fetch_kind: fedimint_client_module::meta::FetchKind,
        last_revision: Option<u64>,
    ) -> anyhow::Result<fedimint_client_module::meta::MetaValues> {
        let backoff = match fetch_kind {
            // need to be fast the first time.
            FetchKind::Initial => backoff_util::aggressive_backoff(),
            FetchKind::Background => backoff_util::background_backoff(),
        };

        let maybe_meta_module_meta = get_meta_module_value(client_config, api, backoff)
            .await
            .map(|meta| {
                Result::<_, anyhow::Error>::Ok(MetaValues {
                    values: serde_json::from_slice(meta.value.as_slice())?,
                    revision: meta.revision,
                })
            })
            .transpose()?;

        // If we couldn't fetch valid meta values from the meta module for any reason,
        // fall back to the legacy meta source
        if let Some(maybe_meta_module_meta) = maybe_meta_module_meta {
            Ok(maybe_meta_module_meta)
        } else {
            self.legacy
                .fetch(client_config, api, fetch_kind, last_revision)
                .await
        }
    }
}

async fn get_meta_module_value(
    client_config: &ClientConfig,
    api: &DynGlobalApi,
    backoff: FibonacciBackoff,
) -> Option<MetaConsensusValue> {
    match client_config.get_first_module_by_kind_cfg(KIND) {
        Ok((instance_id, _)) => {
            let meta_api = api.with_module(instance_id);

            let overrides_res = retry("fetch_meta_values", backoff, || async {
                Ok(meta_api.get_consensus(DEFAULT_META_KEY).await?)
            })
            .await;

            match overrides_res {
                Ok(Some(consensus)) => Some(consensus),
                Ok(None) => {
                    debug!(target: LOG_CLIENT_MODULE_META, "Meta module returned no consensus value");
                    None
                }
                Err(e) => {
                    warn!(target: LOG_CLIENT_MODULE_META, "Failed to fetch meta module consensus value: {}", e);
                    None
                }
            }
        }
        _ => None,
    }
}
