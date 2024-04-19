use std::collections::BTreeMap;

use db::DbKeyPrefix;
use fedimint_client::db::ClientMigrationFn;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::recovery::NoModuleBackup;
use fedimint_client::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client::sm::Context;
use fedimint_core::core::Decoder;
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::{ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion};
use fedimint_core::{apply, async_trait_maybe_send, Amount};
pub use fedimint_empty_common as common;
use fedimint_empty_common::config::EmptyClientConfig;
use fedimint_empty_common::{EmptyCommonInit, EmptyModuleTypes};
use states::EmptyStateMachine;
use strum::IntoEnumIterator;

pub mod api;
pub mod db;
pub mod states;

#[derive(Debug)]
pub struct EmptyClientModule {
    #[allow(dead_code)]
    cfg: EmptyClientConfig,
    #[allow(dead_code)]
    client_ctx: ClientContext<Self>,
    #[allow(dead_code)]
    db: Database,
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct EmptyClientContext {
    pub empty_decoder: Decoder,
}

// TODO: Boiler-plate
impl Context for EmptyClientContext {}

#[apply(async_trait_maybe_send!)]
impl ClientModule for EmptyClientModule {
    type Init = EmptyClientInit;
    type Common = EmptyModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = EmptyClientContext;
    type States = EmptyStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        EmptyClientContext {
            empty_decoder: self.decoder(),
        }
    }

    fn input_fee(&self, _input: &<Self::Common as ModuleCommon>::Input) -> Option<Amount> {
        unreachable!()
    }

    fn output_fee(&self, _output: &<Self::Common as ModuleCommon>::Output) -> Option<Amount> {
        unreachable!()
    }

    fn supports_being_primary(&self) -> bool {
        false
    }

    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>) -> Amount {
        Amount::ZERO
    }
}

#[derive(Debug, Clone)]
pub struct EmptyClientInit;

// TODO: Boilerplate-code
impl ModuleInit for EmptyClientInit {
    type Common = EmptyCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

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
        for _table in filtered_prefixes {
            match _table {}
        }

        Box::new(items.into_iter())
    }
}

/// Generates the client module
#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for EmptyClientInit {
    type Module = EmptyClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(EmptyClientModule {
            cfg: args.cfg().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientMigrationFn> {
        BTreeMap::new()
    }
}
