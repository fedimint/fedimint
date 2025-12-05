#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;

use db::DbKeyPrefix;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client_module::sm::Context;
use fedimint_core::core::{Decoder, ModuleKind};
use fedimint_core::db::{Database, DatabaseTransaction, DatabaseVersion};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::{Amount, apply, async_trait_maybe_send};
pub use fedimint_ecash_migration_common as common;
use fedimint_ecash_migration_common::config::EcashMigrationClientConfig;
use fedimint_ecash_migration_common::{EcashMigrationCommonInit, EcashMigrationModuleTypes};
use states::EcashMigrationStateMachine;
use strum::IntoEnumIterator;

pub mod api;
pub mod db;
pub mod states;

#[derive(Debug)]
pub struct EcashMigrationClientModule {
    #[allow(dead_code)]
    cfg: EcashMigrationClientConfig,
    #[allow(dead_code)]
    client_ctx: ClientContext<Self>,
    #[allow(dead_code)]
    db: Database,
}

/// Data needed by the state machine
#[derive(Debug, Clone)]
pub struct EcashMigrationClientContext {
    pub ecash_migration_decoder: Decoder,
}

// TODO: Boiler-plate
impl Context for EcashMigrationClientContext {
    const KIND: Option<ModuleKind> = None;
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for EcashMigrationClientModule {
    type Init = EcashMigrationClientInit;
    type Common = EcashMigrationModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = EcashMigrationClientContext;
    type States = EcashMigrationStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        EcashMigrationClientContext {
            ecash_migration_decoder: self.decoder(),
        }
    }

    fn input_fee(
        &self,
        _amount: &Amounts,
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

    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        Amount::ZERO
    }
}

#[derive(Debug, Clone)]
pub struct EcashMigrationClientInit;

// TODO: Boilerplate-code
impl ModuleInit for EcashMigrationClientInit {
    type Common = EcashMigrationCommonInit;

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
impl ClientModuleInit for EcashMigrationClientInit {
    type Module = EcashMigrationClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(EcashMigrationClientModule {
            cfg: args.cfg().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}
